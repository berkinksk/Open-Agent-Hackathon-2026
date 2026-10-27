# Evaluation

How well does the system map messy inventory rows to CISA KEV products? This page holds the measured tables. Every number comes from a real run's saved output (`output/eval-*.json`, `output/run-eval-*.json`); none is typed in by hand.

## Development set (not the final test)

- **Rows:** the 50 development rows of the 80-row synthetic inventory. The 30 test rows (`data/eval/test_rows.json`, a seeded random pick) are sealed. They never reached any arm.
- **No accuracy yet.** The human answers for these rows were not available on 27 Oct, so nothing is scored. The tables show what each arm named, how often it agrees with the full system, how stable it is between identical runs, the Ultra share, the calls and the time. **Agreement is not accuracy.**
- **Runs** (all live: Zetaris and Nightshift), on 27 Oct 2026:
  - runs 1 and 2, 01:51 and 01:53 UK: `npm run eval -- --set dev --labels none --arms full,bolt,lightning,normaliser`;
  - run 3, 03:28 UK, after the final fixes, with the one-call baseline arm added: `npm run eval -- --set dev --labels none --arms full,bolt,lightning,baseline,normaliser`.
- **Outputs:** `output/eval-2026-10-27-015127-dev-unlabelled.*`, `output/eval-2026-10-27-015353-dev-unlabelled.*` and `output/eval-2026-10-27-032806-dev-unlabelled.*` (`.md` and `.json`).

### Run 3 (the final code, with the one-call baseline)

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

**What the final fixes changed on these rows.** Run 3 used the final code. The normaliser change (a KEV vendor whose KEV product name is only generic words, such as `WordPress / Core`, gets an unsure vote, never a confident "no KEV product") changed 0 of the 50 dev rows' normaliser votes (a one-variable check, offline, on the same KEV names). The citation fix (a line cites only the KEV CVEs that NVD's ranges do not rule out) changes which CVEs a line cites and its dates, not its match. The differences between run 3 and runs 1–2 (one more `ask_owner`, fewer calls) are within the run-to-run variance of the models.

**Where the arms differ from the full system.** In every case, either a single model (or the one-call baseline) named a KEV product where the full system found none, or the normaliser named none where the full system found one. Examples:
- an online word processor matched to the on-prem desktop product;
- a file-sharing client matched to the vendor's server product;
- a backup agent matched to the vendor's backup server;
- a utilities suite matched to an unrelated vendor's desktop product;
- an open-source VPN client matched to another vendor's VPN appliance (Lightning alone, run 1).

The output files list every such row. Whether each call is right will be settled by the human answers, not by this table.

## Final test

Not run yet. It runs once, on the 30 sealed test rows, with the answers the two labellers agreed (`data/test_answers.csv`):

```bash
npm run eval -- --set test --final --labels data/test_answers.csv --arms full,bolt,lightning,baseline,normaliser
```

- **Scoring is by KEV family:** a prediction is correct when it names the same KEV product family as a spelling the answer lists (any KEV spelling of that product counts, through the normaliser's `familiesOf`), or when the answer is "none" and the arm names no KEV product. The report states which scoring ran.
- **Accuracy and strict accuracy are reported side by side:** abstaining (leaving a row to the owner) on a row whose answer is "none" counts as correct in `accuracy`, but never in `accuracy_strict`.
- **Disclosure: not all 30 test rows are unseen.** The test rows were picked at random from the same synthetic inventory, and three of them are variants of examples the design was built on: R13 (a `log4j-core 2.14.1` row in a web application archive) nearly repeats the design document's worked example, and R46 (Exchange Online) and R68 (FortiClient VPN) are the cloud and client look-alikes the critic's product-type rule was written for (probe P4). No code maps any row to an answer, and no test-row prediction was looked at during development. The final table will report accuracy on all 30 rows and on the other 27, and will not call the test "blind" or "unseen".
