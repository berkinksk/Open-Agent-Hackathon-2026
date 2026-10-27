// Memory index tests (src/pipeline/memory.ts): per-row keys, the run index, grouping rows by their last run. No network.
// The pipeline-level memory tests (two and three live runs, subsets) are in run.test.ts.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { earlierRunsFor, readRunIndex, rowMemoryKey, RUN_INDEX_FILE, writeRunIndex } from "../src/pipeline/memory.ts";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TMP = join(REPO, "output", `test-memory-${process.pid}`);
after(() => rmSync(TMP, { recursive: true, force: true }));

const row = (row_id: string, software: string, asset_id = "A1") => ({ row_id, asset_id, software });

test("rowMemoryKey: the source, the row id, and a hash of the asset and software text", () => {
  const k = rowMemoryKey("zetaris", row("R02", "PAN-OS 10.2.7"));
  assert.match(k, /^inventory:R02:[0-9a-f]{12}$/);
  assert.equal(rowMemoryKey("zetaris", row("R02", "PAN-OS 10.2.7")), k, "stable");
  assert.notEqual(rowMemoryKey("request", row("R02", "PAN-OS 10.2.7")), k, "request rows never share the inventory's memory");
  assert.notEqual(rowMemoryKey("zetaris", row("R02", "PAN-OS 10.2.9")), k, "changed software text: a new row");
  assert.notEqual(rowMemoryKey("zetaris", row("R02", "PAN-OS 10.2.7", "A2")), k, "another asset: a new row");
});

test("the run index: rows point at their last run; runs no row points at are dropped; older formats are ignored", () => {
  const dir = join(TMP, "index");
  assert.deepEqual(readRunIndex(dir), { version: 2, runs: {}, rows: {} }, "absent: empty");
  writeRunIndex(dir, ["k1", "k2"], { run_id: "run-a", namespace: "run-a", as_of: "2026-10-26", rows: 2 });
  writeRunIndex(dir, ["k2"], { run_id: "run-b", namespace: "run-b", as_of: "2026-10-27", rows: 1 });
  let idx = readRunIndex(dir);
  assert.deepEqual(idx.rows, { k1: "run-a", k2: "run-b" });
  assert.deepEqual(Object.keys(idx.runs).sort(), ["run-a", "run-b"]);
  writeRunIndex(dir, ["k1"], { run_id: "run-c", namespace: "run-c", as_of: "2026-10-28", rows: 1 });
  idx = readRunIndex(dir);
  assert.deepEqual(idx.rows, { k1: "run-c", k2: "run-b" });
  assert.deepEqual(Object.keys(idx.runs).sort(), ["run-b", "run-c"], "run-a is no row's last run any more");
  // the earlier build's format (one pointer per list) is not read: memory starts again
  const legacy = join(TMP, "legacy");
  mkdirSync(legacy, { recursive: true });
  writeFileSync(join(legacy, RUN_INDEX_FILE), JSON.stringify({ "zetaris-inventory": { run_id: "x", namespace: "x", as_of: "2026-10-27", rows: 2 } }));
  assert.deepEqual(readRunIndex(legacy), { version: 2, runs: {}, rows: {} });
  writeFileSync(join(legacy, RUN_INDEX_FILE), "not json");
  assert.deepEqual(readRunIndex(legacy), { version: 2, runs: {}, rows: {} });
  // a row pointing at a run the index does not hold is dropped on read
  writeFileSync(join(legacy, RUN_INDEX_FILE), JSON.stringify({ version: 2, runs: {}, rows: { k9: "gone" } }));
  assert.deepEqual(readRunIndex(legacy).rows, {});
  assert.ok(readFileSync(join(dir, RUN_INDEX_FILE), "utf8").endsWith("\n"));
});

test("earlierRunsFor: rows grouped by their last run, most recent first; unknown rows and this run's own id are fresh", () => {
  const idx = {
    version: 2 as const,
    runs: {
      "run-a": { run_id: "run-a", namespace: "run-a", as_of: "2026-10-26", rows: 2 },
      "run-b": { run_id: "run-b", namespace: "run-b", as_of: "2026-10-27", rows: 1 },
    },
    rows: { k1: "run-a", k2: "run-b", k3: "run-a" },
  };
  const rows = [{ row_id: "R1", key: "k1" }, { row_id: "R2", key: "k2" }, { row_id: "R3", key: "k3" }, { row_id: "R4", key: "k4" }];
  const g = earlierRunsFor(idx, rows, "run-now");
  assert.deepEqual(g.runs.map((r) => [r.pointer.run_id, r.row_ids]), [["run-b", ["R2"]], ["run-a", ["R1", "R3"]]]);
  assert.deepEqual(g.fresh, ["R4"]);
  const self = earlierRunsFor(idx, rows, "run-a");
  assert.deepEqual(self.runs.map((r) => r.pointer.run_id), ["run-b"]);
  assert.deepEqual(self.fresh, ["R1", "R3", "R4"]);
});
