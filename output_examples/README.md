# Output examples

These are **real outputs** of three live runs: Zetaris and Meterless Nightshift running, the Nemotron models answering. They are documentation only. The app never reads this folder.

| Input | Command | When (UK) | Files |
|---|---|---|---|
| [`input_examples/example_1.json`](../input_examples/example_1.json) | `npm run cli -- --input input_examples/example_1.json --run-id example-1` | 27 Oct 2026, 15:06 | `example_1.json`, `example_1.trace.jsonl`, `example_1.report.html` |
| [`input_examples/example_2.json`](../input_examples/example_2.json) | `npm run cli -- --input input_examples/example_2.json --run-id example-2` | 27 Oct 2026, 15:07 | `example_2.json`, `example_2.trace.jsonl`, `example_2.report.html` |
| [`input_examples/example_3.json`](../input_examples/example_3.json) | `npm run cli -- --input input_examples/example_3.json --run-id example-3` | 27 Oct 2026, 15:08 | `example_3.json`, `example_3.trace.jsonl`, `example_3.report.html` |

- `example_N.json` is the `RunResponse` the CLI saved as `output/run-example-N.json`.
- `example_N.trace.jsonl` is the run's trace, `logs/trace-example-N.jsonl`: one JSON event per agent step, model call and Zetaris query.
- `example_N.report.html` is the run's HTML report, `output/report-example-N.html`.

The runs used the code at commit `ea2268d`, one run at a time. They reused the run ids of the earlier example runs (`example-N`); a run under an id that already ran replaces that run in the memory index, so each run's "since the last run" step records it as the first run on its rows. The NVD records the runs needed were already in that day's NVD cache (earlier runs that morning, one of them with a larger NVD budget, had read them through Zetaris), so the manifests and evidence label NVD as cached with its day, not live (0 live NVD reads in each run); KEV and EPSS (and example 1's inventory) were read live.

**The one change made after the runs:** local absolute file paths (the `trace_file` and `report_file` fields, and file paths inside a few trace summaries) were shortened to repo-relative paths such as `logs/trace-example-1.jsonl`. Nothing else was edited. The files were then checked for secret values, absolute local paths and identifying text (none found).

Check the receipts in a trace:

```bash
npm run verify -- --only receipts --trace output_examples/example_1.trace.jsonl
```

Model answers can vary slightly between identical runs, and KEV and EPSS change daily, so a new run of the same input may differ from these files.
