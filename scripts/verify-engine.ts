// Official checks for the vendored Meterless World Model engine (src/engine/world-model).
//
//   npm run verify:engine            human-readable summary; exit 1 if any check fails
//   npm run verify:engine -- --json  the same result as one JSON object
//
// Checks:
//   0. the vendored files still match SHA256SUMS (the copy is unmodified);
//   1. the official conformance runner passes 8/8 against the vendored reference;
//   2. the idempotency check prints "diff: empty" (re-ingest changes nothing);
//   3. the idempotency check with --mutate prints "diff: NON-EMPTY" (proof the check can fail).
//      The upstream script exits 0 in this case, so the text is what we assert on.
// No network, no install: plain Node with --experimental-transform-types.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(here, "..");
export const ENGINE_DIR = path.join(REPO_ROOT, "src", "engine", "world-model");
const REFERENCE_DIR = path.join(ENGINE_DIR, "reference");
const IMPL_PATH = path.join(REFERENCE_DIR, "src", "index.ts"); // absolute, as the runner requires
const NODE_FLAGS = ["--experimental-transform-types", "--no-warnings"];
const STEP_TIMEOUT_MS = 60_000;
const EXPECTED_CHECKS = 8;

export interface EngineCheck {
  name: string;
  command: string;
  ok: boolean;
  expected: string;
  observed: string;
  exit_code: number | null;
  ms: number;
}

export interface EngineVerifyResult {
  ok: boolean;
  engine_dir: string;
  impl: string;
  checks: EngineCheck[];
  conformance_lines: string[];
}

function runNode(args: string[], extraEnv: Record<string, string> = {}): { code: number | null; out: string; ms: number } {
  const t0 = performance.now();
  // A minimal environment: the engine needs only PATH, so nothing else from the parent env reaches the child.
  const env: Record<string, string> = { PATH: process.env.PATH ?? "", ...extraEnv };
  const r = spawnSync(process.execPath, [...NODE_FLAGS, ...args], {
    cwd: REFERENCE_DIR, env, encoding: "utf-8", timeout: STEP_TIMEOUT_MS,
  });
  const out = `${r.stdout ?? ""}${r.stderr ?? ""}${r.error ? `\n${r.error.message}` : ""}`;
  return { code: r.status, out, ms: Math.round(performance.now() - t0) };
}

function checkSums(): EngineCheck {
  const t0 = performance.now();
  const sumsFile = path.join(ENGINE_DIR, "SHA256SUMS");
  const problems: string[] = [];
  let count = 0;
  if (!fs.existsSync(sumsFile)) {
    problems.push("SHA256SUMS missing");
  } else {
    for (const line of fs.readFileSync(sumsFile, "utf-8").split("\n")) {
      const m = /^([0-9a-f]{64})\s+\*?(.+)$/.exec(line.trim());
      if (!m) continue;
      count++;
      const file = path.join(ENGINE_DIR, m[2]);
      if (!fs.existsSync(file)) {
        problems.push(`${m[2]} missing`);
        continue;
      }
      const digest = createHash("sha256").update(fs.readFileSync(file)).digest("hex");
      if (digest !== m[1]) problems.push(`${m[2]} modified`);
    }
    if (count === 0) problems.push("SHA256SUMS lists no files");
  }
  return {
    name: "vendored files unmodified",
    command: "sha256 of each file in src/engine/world-model/SHA256SUMS",
    ok: problems.length === 0,
    expected: "every listed file present with the recorded SHA-256",
    observed: problems.length ? problems.join("; ") : `${count}/${count} files match`,
    exit_code: null,
    ms: Math.round(performance.now() - t0),
  };
}

export function verifyEngine(): EngineVerifyResult {
  const checks: EngineCheck[] = [checkSums()];

  const conf = runNode([path.join("..", "conformance", "runner.ts")], { WORLD_MODEL_IMPL: IMPL_PATH });
  const score = /(\d+)\/(\d+) checks passed/.exec(conf.out);
  const passed = score ? Number(score[1]) : -1;
  const total = score ? Number(score[2]) : -1;
  checks.push({
    name: "conformance runner",
    command: "WORLD_MODEL_IMPL=<abs>/src/engine/world-model/reference/src/index.ts node --experimental-transform-types --no-warnings ../conformance/runner.ts",
    ok: conf.code === 0 && passed === EXPECTED_CHECKS && total === EXPECTED_CHECKS,
    expected: `${EXPECTED_CHECKS}/${EXPECTED_CHECKS} checks passed, exit 0`,
    observed: `${score ? score[0] : "no score line"}, exit ${conf.code}`,
    exit_code: conf.code,
    ms: conf.ms,
  });
  const conformanceLines = conf.out.split("\n").map((l) => l.trim()).filter((l) => /^(PASS|FAIL) /.test(l));

  const idem = runNode([path.join("scripts", "idempotency-check.ts")]);
  checks.push({
    name: "idempotency check",
    command: "node --experimental-transform-types --no-warnings scripts/idempotency-check.ts",
    ok: idem.code === 0 && /diff: empty/.test(idem.out) && !/NON-EMPTY/.test(idem.out),
    expected: "diff: empty, exit 0",
    observed: `${(/diff: \S+/.exec(idem.out) ?? ["no diff line"])[0]}, exit ${idem.code}`,
    exit_code: idem.code,
    ms: idem.ms,
  });

  const mut = runNode([path.join("scripts", "idempotency-check.ts"), "--mutate"]);
  checks.push({
    name: "idempotency check can fail (--mutate)",
    command: "node --experimental-transform-types --no-warnings scripts/idempotency-check.ts --mutate",
    ok: /diff: NON-EMPTY/.test(mut.out),
    expected: "diff: NON-EMPTY (the upstream script still exits 0, so the text is asserted)",
    observed: `${(/diff: \S+/.exec(mut.out) ?? ["no diff line"])[0]}, exit ${mut.code}`,
    exit_code: mut.code,
    ms: mut.ms,
  });

  return {
    ok: checks.every((c) => c.ok),
    engine_dir: path.relative(REPO_ROOT, ENGINE_DIR),
    impl: path.relative(REPO_ROOT, IMPL_PATH),
    checks,
    conformance_lines: conformanceLines,
  };
}

function main(): void {
  const result = verifyEngine();
  if (process.argv.includes("--json")) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`World Model engine checks (${result.engine_dir}, Meterless/Meterless@1742dec, Apache-2.0)`);
    for (const line of result.conformance_lines) console.log(`  conformance: ${line}`);
    for (const c of result.checks) {
      console.log(`  ${c.ok ? "PASS" : "FAIL"} ${c.name}: ${c.observed} (expected ${c.expected}; ${c.ms} ms)`);
    }
    const n = result.checks.filter((c) => c.ok).length;
    console.log(`verify:engine ${result.ok ? "OK" : "FAILED"}: ${n}/${result.checks.length} engine checks passed`);
  }
  process.exit(result.ok ? 0 : 1);
}

const invoked = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invoked === fileURLToPath(import.meta.url)) main();
