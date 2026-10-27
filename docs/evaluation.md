# Evaluation

How well does the system map messy inventory rows to CISA KEV products? This page holds the measured tables. Every number comes from a real run's saved output (`output/eval-*.json`); none is typed in by hand.

## Development set (not the final test)

- **Rows:** the 50 development rows of the 80-row synthetic inventory. The 30 test rows (`data/eval/test_rows.json`, a seeded random pick) are sealed. They never reached any arm.
- **No accuracy yet.** The human answers for these rows were not available on 27 Oct, 01:51 UK, so nothing is scored. The table shows what each arm named, how often it agrees with the full system, how stable it is between two identical runs, the Ultra share, the calls and the time. **Agreement is not accuracy.**
- **Command:** `npm run eval -- --set dev --labels none --arms full,bolt,lightning,normaliser`. It ran twice, live (Zetaris and Nightshift), on 27 Oct 2026, 01:51 and 01:53 UK. Where the two runs differ, both values are shown.
- **Outputs:** `output/eval-2026-10-27-015127-dev-unlabelled.{md,json}` and `output/eval-2026-10-27-015353-dev-unlabelled.{md,json}`.

| Arm | Named a KEV product | No KEV product | Left to the owner | Agrees with the full system¹ | Answers changed between the 2 runs | Model calls (Ultra) | Time |
|---|---|---|---|---|---|---|---|
| Full system (jury + Ultra + critic) | 28 | 18 | 4 | – | 0 of 50 | 27 (15) | 69.5 s / 54.7 s² |
| Bolt alone | 36 / 35 | 14 / 15 | 0 | 42/46 / 43/46 | 2 of 50 | 5 (0) | 10.9 s |
| Lightning alone | 39 / 36 | 8 / 12 | 0 (3 / 2 rows without a valid vote) | 35/44 / 40/45 | 6 of 50 | 5 (0) | 19.9 s / 13.3 s |
| Normaliser alone (no model) | 27 | 23 | 0 | 40/46 | 0 of 50 | 0 | 0.4 s |

¹ Counted on the rows both answered: the same KEV family (any spelling), or both "no KEV product". The 4 rows the full system leaves to the owner are not compared.
² The full system's time covers the whole pipeline: Zetaris queries, jury, critic loop, NVD version ranges, policy, live verifier and World Model, not only matching. In run 1, 5 NVD records were read live and 15 came from that day's cache. Run 2 used the cache only.

**Full system, both runs:**
- **Decisions:** 25 `patch_now`, 0 `this_cycle` (the NVD product lookup is dormant), 21 `monitor`, 4 `ask_owner`; 12 owner questions.
- **Checks:** 50 of 50 lines verified; 27 of 27 model calls receipted with the pinned model.
- **Ultra:** decided 9 of the 50 rows (18%), the rows where Bolt and Lightning split. It worked on 15 / 14 rows (30% / 28%) in any role (split, critique, same-product check, re-decide), and made 15 of the 27 calls.

**Where the arms differ from the full system.** In every case, either a single model named a KEV product where the full system found none, or the normaliser named none where the full system found one. Examples:
- an online word processor matched to the on-prem desktop product;
- a file-sharing client matched to the vendor's server product;
- a backup agent matched to the vendor's backup server;
- a utilities suite matched to an unrelated vendor's desktop product;
- an open-source VPN client matched to another vendor's VPN appliance (Lightning alone, run 1).

The output files list every such row. Whether each call is right will be settled by the human answers, not by this table.

## Final test

Not run yet. It runs once, on the 30 sealed test rows, with the answers the two labellers agreed (`npm run eval -- --set test --final --labels data/test_answers.csv`). Its table will go here.
