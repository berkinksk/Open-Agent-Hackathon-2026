# Open-Agent-Hackathon-2026
Team Megatron's Interns, GenAI.works Open Agent Hackathon 2026. A multi-agent AI system using Zetaris as the data layer, a Meterless engine, and NVIDIA Nemotron models through Meterless Nightshift.

## How to run

**Prerequisites**
- Node.js 25 or newer. There is nothing to install: the app has zero runtime dependencies and runs its TypeScript directly with `node --experimental-transform-types` (the npm scripts pass the flags).
- Live mode: Zetaris running locally (REST on `http://localhost:8888`) and the Meterless Nightshift app open (`http://127.0.0.1:8088`).
- Sample mode (`SAMPLE_MODE=true` or `--sample`) needs neither, and makes no network calls.

**1. Configure**
```bash
cp .env.example .env      # then fill in ZETARIS_API_KEY and METERLESS_RUNTIME_TOKEN
```
The scripts read `.env` automatically. For Docker, use `.env.docker.example`.

**2. Register the data sources in Zetaris** (idempotent; safe to re-run)
```bash
npm run setup                       # EL_INVENTORY, EL_KEV, EL_EPSS, EL_NVD; container el; views el.inventory, el.kev
npm run setup -- --dry-run          # print the SQL without sending it
npm run setup -- --prefix EL_T1_    # the same objects under a fresh prefix
```
Existing objects are detected (`SHOW LIGHTNING DATABASES` / `TABLES`) and never dropped. Setup ends with one `LIMIT 1` query per object and prints a table.

**3. Run**
```bash
npm run cli -- --input input_examples/example_1.json             # one run; prints the counts and the output paths
npm run cli -- --input input_examples/example_1.json --sample    # the same, offline
npm run cli -- --rows R01,R02                                    # selected rows of the inventory registered in Zetaris
npm start                                                        # HTTP API on 0.0.0.0:8000 (PORT to change)
```
```bash
curl -s localhost:8000/health
curl -s -X POST localhost:8000/run -H 'Content-Type: application/json' -d @input_examples/example_1.json
# then open http://localhost:8000/report/<run_id>
```
- `POST /run` takes a JSON `RunRequest`: `{"run_id"?, "inventory"?: [rows], "row_ids"?: [...], "sample_mode"?: true|false, "policy"?: {...}}`. Each row needs only `software`; `row_id`, `asset_name`, `internet_facing` and the rest are optional. Without `inventory`, the run reads `el.inventory` through Zetaris.
- It returns a `RunResponse` (the dated patch list, receipts, manifest), or a structured error: `{"status": "error", "error": {"type", "message", "recoverable"}}`.
- Outputs: `output/run-<run_id>.json`, `output/report-<run_id>.html`, and the trace `logs/trace-<run_id>.jsonl` (also printed to stdout).
