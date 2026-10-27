# Evaluation

How well does the system map messy inventory rows to CISA KEV products? This page holds the measured tables: first the final test on the 30 sealed test rows, run once, then the development runs that came before it. Every measured number comes from a real run's saved output, or is counted from its per-row results. The final test's output files are committed in [`eval/final-test/`](eval/final-test/) (listed [below](#the-files)); the development runs' files (`output/eval-*`) are not committed.

## Final test (30 sealed rows, one run)

**0 wrong answers on 30 held-out rows (one run): 23 of 23 answered rows right; 7 sent to the owner with a question instead of a decision.**

In the same run, one Ultra call, given all 30 rows and the union of our normaliser's candidate shortlists, named the right KEV product (or none) for all 30 rows. It was the most accurate arm in this test.

### Method
- **Rows:** 30 rows picked at random from the 80-row synthetic inventory and sealed during development ([`data/eval/test_rows.json`](../data/eval/test_rows.json)). The seed is the SHA-256 of the software list file; each row is ranked by `sha256(seed:row_id)` and the first 30 are taken. No test-row prediction was looked at before this run, and no code maps any row to an answer.
- **Answers:** written independently by two teammates, following the labelling rules: the exact KEV vendor and product names (every KEV spelling of the product), or "none"; the same vendor is not enough; versions are ignored. Where they differed (8 of the 30 rows), one of their two answers was chosen per row, following the labelling rules, so every final answer is one of theirs, unchanged. The file is [`data/test_answers.csv`](../data/test_answers.csv) (SHA-256 `25dce62701bc6032906d2727f46fe8b3aca0d57300561ab2353b85df640d7a38`), byte-identical to the one the run used.
- **Scoring:** by KEV product family. A prediction is right when it names the same KEV product family as a spelling the answer lists (any KEV spelling of that product counts, through the normaliser's `familiesOf`), or when the answer is "none" and the arm names no KEV product. *Correct* also counts a "none" row left to the owner as right; *strict* counts every row left to the owner as not answered. For the full system, an `ask_owner` line counts as left to the owner, and a `patch_now` line whose version is unconfirmed counts as its match.
- **One run,** live (Zetaris and Nightshift), on 27 Oct 2026 at 15:26 UK, on commit `e1edc33`, with the default arms (full, bolt, lightning, baseline, normaliser) run one after another. With the same answer file, on commit `e1edc33`, the command is `npm run eval -- --set test --final --labels data/test_answers.csv` (model answers vary between runs; on later commits these 30 rows are no longer held out).

### Results

| Arm | Correct (strict) | Wrong | Left to the owner | Model calls | Time¹ |
|---|---|---|---|---|---|
| **Full system** (jury + Ultra + critic) | 25/30 (strict 23/30) | **0** | 7 | 20: Bolt 3, Lightning 5, Ultra 12 | 188.5 s |
| Bolt alone | 26/30 (strict 26/30) | 4² | 0 | 3 | 7.6 s |
| Lightning alone | 23/30 (strict 23/30) | 6², and 1 row with no valid answer | 0 | 3 | 8.7 s |
| **One Ultra call** (the one-call baseline): all 30 rows plus the union of our normaliser's candidate shortlists (120 KEV vendor/product pairs) in one prompt | **30/30** (strict 30/30) | 0 | 0 | 1 | 10.9 s |
| Normaliser alone (code, no model) | 25/30 (strict 25/30) | 5³ | 0 | 0 | 1.1 s |

¹ Each arm's wall-clock time in this run. The full system's covers the whole pipeline: Zetaris queries, NVD version ranges, the jury, the critic loop, the policy, the live verifier and the World Model. It includes 55.3 s of NVD lookups (5 records read live through Zetaris, 9 from that day's cache), and one Lightning jury call that failed with HTTP 502 and succeeded on retry. The other arms only build the candidate lists and make their model calls.
² A KEV product named for a row whose answer is "none".
³ KEV-listed rows it named no product for.

| Arm | Bolt calls | Lightning calls | Ultra calls | Prompt tokens | Completion tokens | Total tokens |
|---|---|---|---|---|---|---|
| Full system | 3 | 5 | 12 | 32,762 | 5,025 | 37,787 |
| Bolt alone | 3 | 0 | 0 | 7,107 | 966 | 8,073 |
| Lightning alone | 0 | 3 | 0 | 7,262 | 1,401 | 8,663 |
| One Ultra call | 0 | 0 | 1 | 2,959 | 506 | 3,465 |
| Normaliser alone | 0 | 0 | 0 | 0 | 0 | 0 |

The one Ultra call was the most accurate arm, with the fewest calls (1) and tokens (3,465) of the model arms. The full system made the most calls (20), used the most tokens (37,787) and took the longest (188.5 s, for the whole pipeline). Besides matching, it checks versions against NVD, re-reads every cited KEV and EPSS value live, and writes the dated decisions and the owner questions; the one-call baseline only names a product per row.

### Safety (this test only)

| Rows | Full system | Bolt alone | Lightning alone | One Ultra call | Normaliser alone |
|---|---|---|---|---|---|
| **18 rows whose answer is a KEV product:** matched / sent to the owner / named no KEV product | 13 / 5 / **0** | 18 / 0 / 0 | 18 / 0 / 0 | 18 / 0 / 0 | 13 / 0 / 5 |
| **12 rows with no KEV product:** matched to a KEV product / rejected / sent to the owner | **0** / 10 / 2 | 4 / 8 / 0 | 6 / 5 / 0 (1 with no valid answer) | 0 / 12 / 0 | 0 / 12 / 0 |

- In this test, the full system gave "no KEV product" as its answer for none of the 18 KEV-listed rows, and a KEV product for none of the 12 rows without one: 10 were rejected and 2 went to the owner. In the run file, three of the rows sent to the owner keep the resolver's last answer: "no KEV product" for R78, and the look-alike for R70 and R76 (their questions are below).
- Inside the full system, both jurors also matched "Exchange Online" to Exchange. The critic's product-type rule (a cloud service is not the on-premises server) sent it back, Lightning's re-decide answered "no KEV product", and Ultra's critique approved that answer.
- Alone, Bolt matched 4 of those 12 rows to a KEV product and Lightning 6. Both matched "Exchange Online (Microsoft 365 mail in browser)" to Microsoft's on-premises Exchange, "PaperCut Mobility Print client v1.0" to PaperCut NG/MF and "Apache NetBeans IDE 22 - desktop editor" to Apache Struts. Bolt also matched "FortiClient VPN 7.2.4; endpoint client" to the FortiClient EMS server; Lightning also matched a GlobalProtect VPN client to Palo Alto Networks Expedition, WinSCP to Microsoft Visual Basic for Applications, and paint.net to Progress Telerik UI for ASP.NET AJAX.

### Why 7 rows went to the owner

Each of these rows is an `ask_owner` line in the full system's run. The votes, the critic's reasons and the questions below are as the run wrote them (the run file's `lines` and `owner_questions`).

| Row | Software (as written) | Answer | Votes | Why the critic held it | The owner question |
|---|---|---|---|---|---|
| R03 | Veeam B&R 12.0 - backup console | Veeam / Backup & Replication | Bolt, Lightning and the normaliser: Veeam / Backup & Replication | Sent back once for NVD's version ranges; "12.0" is too vague to place in them. Rubric 6/9 (accuracy 3, appropriateness 1, actionability 2) | "Which exact Backup & Replication version or build runs on backup-01? "12.0" is too vague to place in NVD's affected ranges for CVE-2023-27532, CVE-2024-40711." |
| R04 | Windows11 Pro 23H2 | Microsoft / Windows | Bolt and Lightning: Microsoft / Windows; the normaliser: no KEV product (type unknown) | The normaliser's dissent lowered the accuracy score to 2: rubric 6/9 (2, 2, 2), below the 7/9 an automatic line needs | "Which exact Windows version or build runs on shared-pc-01? "23H2" is too vague to place in NVD's affected ranges for CVE-2026-96951." |
| R38 | MS Windows11 Pro, 23H2 | Microsoft / Windows | as R04 | as R04 | as R04, for ops-laptop-03 |
| R52 | Windows10 Pro 22H2, build not written | Microsoft / Windows | as R04 | as R04 | as R04, for fin-laptop-03 ("22H2") |
| R78 | MS Win Server 2022 Standard (backup host) | Microsoft / Windows | Bolt, Lightning and the normaliser: Microsoft / Windows; the normaliser typed the row "server" | "type conflict: server vs operating system", so it was sent back twice: Lightning's re-decide gave no valid answer, and Ultra's answered "no KEV product". Rubric 6/9 (1, 2, 3) | "Please confirm: is "MS Win Server 2022 Standard (backup host)" on backup-01 absent from the KEV catalogue (no KEV product matches it)?" |
| R70 | PaperCut Mobility Print client v1.0 | none | Bolt and Lightning: PaperCut / NG/MF; the normaliser: no KEV product | Sent back for NVD's ranges; Ultra's critique then judged it a different product and sent it back; Lightning's re-decide named the same product by another KEV spelling (MF/NG). Rubric 4/9 (1, 1, 2) after two send-backs | "Is MF/NG 1.0 on ops-laptop-02 affected by CVE-2023-27350? NVD could not be consulted; please check the vendor advisory." |
| R76 | Apache NetBeans IDE 22 - desktop editor | none | Bolt and Lightning: Apache / Struts; the normaliser: no KEV product | No version in the row, but the KEV CVEs need a version check. Rubric 5/9 (2, 1, 2): to the owner in the first round | "Which Struts version runs on comms-laptop-02?" |

- **4 of the 7 questions named the right product and asked only for a version or build** (R03, R04, R38, R52).
- **3 did not.** R78's asks the owner to confirm a wrong "no KEV product". R70's and R76's name the look-alike both small models had matched, on rows whose answer is "none".
- None of the 7 became a `patch_now` or `monitor` line: each waits for the owner's answer.
- **What led there, in this run:**
  - R04, R38 and R52 are the only Windows rows in the test that write the number joined to "Windows" ("Windows11", "Windows10"). The normaliser did not read them as Windows: it typed them "unknown" and voted "no KEV product". The 8 Windows rows it read as a Windows operating system (written "Win 11", "Win11", "Windows 11", "Windows 10" or "Windows Svr") reached 7/9 and became `patch_now` lines ("install the latest cumulative update") with one build question per Windows edition.
  - R78: the normaliser read "Win Server 2022" as an application server, so the critic's rule that an operating system and an application are different types fired on a correct match.
  - R03: the jurors and the normaliser agreed on the product, but NVD's ranges could not place "12.0".
  - R70 and R76: both small models agreed on a look-alike, and the critic's version check and rubric held both.
- **Changed after the test:** the normaliser now reads Windows written as one word ("Windows11", "Windows10Enterprise") and "Win Server" as the Windows operating system (the causes of R04, R38, R52 and R78 above). The change was checked on new strings, the 50 development rows and the example inputs only. The test was not re-run, so every final-test number on this page is for the tested code (`e1edc33`), and on later commits these 30 rows are no longer held out.

### The 27 rows that are not variants of the design's examples

This figure was announced before the test, on this page and in the README (both since commit `c1d0fd4`). Three test rows are variants of examples the design was built on: R13 (a `log4j-core 2.14.1` row in a web application archive) nearly repeats the design document's worked example, and R46 (Exchange Online) and R68 (FortiClient VPN) are the cloud and client look-alikes the critic's product-type rule was written for (probe P4). So the test is not called "blind" or "unseen". Without those three rows:

| Arm | Correct (strict) | Wrong | Left to the owner |
|---|---|---|---|
| Full system | 22/27 (strict 20/27) | 0 | 7 |
| Bolt alone | 25/27 (strict 25/27) | 2 | 0 |
| Lightning alone | 22/27 (strict 22/27) | 5 | 0 |
| One Ultra call | 27/27 (strict 27/27) | 0 | 0 |
| Normaliser alone | 22/27 (strict 22/27) | 5 | 0 |

### Windows rows and the others

When the rows were drawn (26 Oct), 12 of the 30 turned out to be Windows rows, by chance. The pick was kept as drawn, because drawing again after seeing it would be cherry-picking, and a per-category breakdown was noted as the way to show it:

| Rows | Full system | Bolt alone | Lightning alone | One Ultra call | Normaliser alone |
|---|---|---|---|---|---|
| 12 Windows rows | 8/12 (strict 8/12), 0 wrong, 4 to the owner | 12/12 | 12/12 | 12/12 | 9/12 (3 wrong) |
| 18 other rows | 17/18 (strict 15/18), 0 wrong, 3 to the owner | 14/18 (4 wrong) | 11/18 (6 wrong, 1 with no valid answer) | 18/18 | 16/18 (2 wrong) |

On the Windows rows, every model alone was right, and the full system left 4 rows to the owner. On the other 18 rows, the full system gave no wrong answer, where Bolt alone gave 4 and Lightning alone 6.

### What we learned
- **In this test, Ultra was the strongest matcher,** and it is already the pipeline's arbiter. In this run it decided all 7 jury splits (in one call), critiqued contested rows 9 times, checked 1 version-unconfirmed `patch_now` line ("same product?") and made 1 re-decide: 12 of the 20 calls.
- **No single model is trusted alone.** In our first probe (26 Oct, 10 strings), all three models, Ultra included, matched "Exchange Online" to the on-premises Exchange Server and "FortiClient VPN" to the FortiClient EMS server (probe P4). In this test, after the critic's wrong objection, Ultra's re-decide called the Windows Server row (R78) "no KEV product".
- **Holding a row has a cost.** In this test, the critic's holds cost 7 owner questions and no wrong answer, and 3 of the 7 questions started from a wrong guess.
- **Next step: Ultra-first matching,** with the small models as cross-checks.

### Other measures from the full system's run
- **Decisions:** 12 `patch_now` (9 of them version unconfirmed, each covered by an owner question), 0 `this_cycle`, 11 `monitor`, 7 `ask_owner`; 11 owner questions.
- **Jury:** 21 rows agreed, 7 split (all 7 decided by Ultra), 2 with no KEV candidate (no model call).
- **Verifier:** 19 lines re-checked live in Zetaris and matched, 11 with nothing to re-check, 0 blocked.
- **Receipts:** 20 of 20 model calls carry a Nightshift receipt and the pinned routed model.

### The files
In [`eval/final-test/`](eval/final-test/), copied from the run's outputs:

| File | What it holds |
|---|---|
| [`eval-2026-10-27-152613-test.md`](eval/final-test/eval-2026-10-27-152613-test.md) | the scored table, as the eval script wrote it |
| [`eval-2026-10-27-152613-test.json`](eval/final-test/eval-2026-10-27-152613-test.json) | every arm's metrics, and every row of every arm: the prediction, the answer and the outcome |
| [`eval-2026-10-27-152613-test-full.json`](eval/final-test/eval-2026-10-27-152613-test-full.json) | the full system's `RunResponse`: the 30 lines (votes, critic verdicts and reasons, decisions, evidence), the 11 owner questions and the 20 receipts |
| [`eval-2026-10-27-152613-test-full.trace.jsonl`](eval/final-test/eval-2026-10-27-152613-test-full.trace.jsonl) | the full system's trace, 150 events: jury votes and splits, Ultra's decisions, the critic's send-backs and re-decides, Zetaris queries, NVD lookups, the verifier and the World Model |
| [`eval-2026-10-27-152613-test-full.report.html`](eval/final-test/eval-2026-10-27-152613-test-full.report.html) | the full system's HTML report |

The one change after the run: the local absolute path prefix was removed from 7 file paths (2 in the run file, 5 in the trace), as in `output_examples/`. Nothing else was edited. The files were checked for secret values, absolute paths and identifying text. The receipts check runs on the committed trace:

```text
$ npm run verify -- --only receipts --trace docs/eval/final-test/eval-2026-10-27-152613-test-full.trace.jsonl
PASS  receipts    eval-2026-10-27-152613-test-full.trace.jsonl: 20/20 model calls carry a receipt_id and a pinned routed_model (bolt 3, lightning 5, ultra 12); 1 failed call(s) had no receipt and were not counted [chosen with --trace]
```

(The failed call is the Lightning attempt that returned HTTP 502; its retry is one of the 20.)

## Development set (before the final test)

- **Rows:** the 50 development rows of the 80-row synthetic inventory. The 30 test rows (`data/eval/test_rows.json`, a seeded random pick) were sealed: they never reached any arm in these runs.
- **Not scored.** The human answers for these rows were not available when these runs were made, so nothing is scored. The tables show what each arm named, how often it agrees with the full system, how stable it is between identical runs, the Ultra share, the calls and the time. **Agreement is not accuracy.**
- **Runs** (all live: Zetaris and Nightshift), on 27 Oct 2026:
  - runs 1 and 2, 01:51 and 01:53 UK: `npm run eval -- --set dev --labels none --arms full,bolt,lightning,normaliser`;
  - run 3, 03:28 UK, after the final fixes, with the one-call baseline arm added: `npm run eval -- --set dev --labels none --arms full,bolt,lightning,baseline,normaliser`.
- **Outputs:** `output/eval-2026-10-27-015127-dev-unlabelled.*`, `output/eval-2026-10-27-015353-dev-unlabelled.*` and `output/eval-2026-10-27-032806-dev-unlabelled.*` (`.md` and `.json`).

### Run 3 (the code of 03:28 UK, with the one-call baseline)

| Arm | Named a KEV product | No KEV product | Left to the owner | Agrees with the full system¹ | Model calls (Ultra) | Tokens | Time |
|---|---|---|---|---|---|---|---|
| Full system (jury + Ultra + critic) | 28 | 17 | 5 | – | 23 (11) | 51,633 | 68.6 s² |
| Bolt alone | 35 | 15 | 0 | 42/45 | 5 (0) | 14,463 | 10.1 s |
| Lightning alone | 37 | 12 | 0 (+1 without a valid vote) | 40/45 | 5 (0) | 15,578 | 8.7 s |
| One-call baseline (Ultra, given every row and every candidate in one prompt) | 32 | 18 | 0 | 42/45 | 1 (1) | 5,421 | 10.9 s |
| Normaliser alone (no model) | 27 | 23 | 0 | 40/45 | 0 | 0 | 0.5 s |

### Runs 1 and 2 (stability between two identical runs)

| Arm | Named a KEV product | No KEV product | Left to the owner | Agrees with the full system¹ | Answers changed between the 2 runs | Model calls (Ultra) | Time |
|---|---|---|---|---|---|---|---|
| Full system (jury + Ultra + critic) | 28 | 18 | 4 | – | 0 of 50 | 27 (15) | 69.5 s / 54.7 s² |
| Bolt alone | 36 / 35 | 14 / 15 | 0 | 42/46 / 43/46 | 2 of 50 | 5 (0) | 10.9 s |
| Lightning alone | 39 / 36 | 8 / 12 | 0 (3 / 2 rows without a valid vote) | 35/44 / 40/45 | 6 of 50 | 5 (0) | 19.9 s / 13.3 s |
| Normaliser alone (no model) | 27 | 23 | 0 | 40/46 | 0 of 50 | 0 | 0.4 s |

¹ Counted on the rows both answered: the same KEV family (any spelling), or both "no KEV product". The rows the full system leaves to the owner are not compared.
² The full system's time covers the whole pipeline: Zetaris queries, jury, critic loop, NVD version ranges, policy, live verifier, the plain SQL join and the World Model, not only matching.

**Full system:**
- **Decisions:** runs 1 and 2: 25 `patch_now`, 0 `this_cycle` (the NVD product lookup is dormant), 21 `monitor`, 4 `ask_owner`, 12 owner questions. Run 3: 25 / 0 / 20 / 5, 13 owner questions.
- **Checks (verifier):** no line was blocked in any run. "Re-checked" means the verifier compared the line's cited KEV and EPSS values with fresh single-source Zetaris reads; a line that cites none (a "no KEV product" line) has nothing to re-check, and is counted apart. Run 1: 28 re-checked and matched, 22 with nothing to re-check. Run 2: 29 and 21. Run 3: 29 and 21.
- **Receipts:** 27 of 27 (runs 1, 2) and 23 of 23 (run 3) model calls carry a receipt and the pinned routed model.
- **Ultra:** in runs 1 and 2 it decided 9 of the 50 rows (18%), the rows where Bolt and Lightning split, and worked on 15 / 14 rows in any role (split, critique, same-product check, re-decide). In run 3 it decided 6 splits and worked on 11 rows.
- **The plain SQL join** (run 3; one federated SQL inside Zetaris that matches a row when a KEV product name appears in its software text): it hits 35 of the 50 rows. 16 agree with the agents; 14 are look-alikes the agents found no KEV product for; 5 name another product than the agents' match; and it misses 8 rows the agents resolve (1 more is left to the owner).

**What the final fixes changed on these rows.** Run 3 used the code of 03:28 UK, after the overnight fixes; the tested commit (`e1edc33`) came later. The normaliser change (a KEV vendor whose KEV product name is only generic words, such as `WordPress / Core`, gets an unsure vote, never a confident "no KEV product") changed 0 of the 50 dev rows' normaliser votes (a one-variable check, offline, on the same KEV names). The citation fix (a line cites only the KEV CVEs that NVD's ranges do not rule out) changes which CVEs a line cites and its dates, not its match. The differences between run 3 and runs 1–2 (one more `ask_owner`, fewer calls) are within the run-to-run variance of the models.

**Where the arms differ from the full system.** In every case, either a single model (or the one-call baseline) named a KEV product where the full system found none, or the normaliser named none where the full system found one. Examples:
- an online word processor matched to the on-prem desktop product;
- a file-sharing client matched to the vendor's server product;
- a backup agent matched to the vendor's backup server;
- a utilities suite matched to an unrelated vendor's desktop product;
- an open-source VPN client matched to another vendor's VPN appliance (Lightning alone, run 1).

The output files list every such row. This table does not say which arm is right on these rows; the final test above scores the 30 test rows against human answers.
