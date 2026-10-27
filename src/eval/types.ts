// Shared types for the accuracy evaluation (src/eval/**). Contract types come from src/contracts.ts.
import type { InventoryRow, ModelKey, Receipt } from "../contracts.ts";

/** The arms the evaluation can compare. `baseline` = one model call given every row and all candidates. */
export const ARM_NAMES = ["full", "bolt", "lightning", "baseline", "normaliser", "ultra"] as const;
export type ArmName = (typeof ARM_NAMES)[number];
export const DEFAULT_ARMS: ArmName[] = ["full", "bolt", "lightning", "baseline", "normaliser"];

export type EvalSet = "dev" | "test";

/** One human answer, from a sheet with the columns row_id, software, kev_vendor, kev_products, notes. */
export interface AnswerRow {
  row_id: string;            // canonical (trimmed, upper-case)
  software: string;
  kev_vendor: string | null; // null when the answer is "none"
  kev_vendors: string[];     // the vendor spellings (";"-separated in the sheet); empty when none
  kev_products: string[];    // every accepted KEV product spelling; empty when none
  is_none: boolean;          // the product is not in KEV
  notes: string;
  unsure: boolean;           // the notes say "unsure"
  lookalike: boolean;        // the notes tag the row as a look-alike
  line: number;              // 1-based line in the CSV, for messages
}

export interface SheetIssue { row_id: string | null; line: number; problem: string; }

export interface AnswerSheet {
  source: string;            // a label for messages (file base name), never a full path
  rows: AnswerRow[];
  issues: SheetIssue[];      // blank answers, malformed rows, duplicates
}

/** What an arm predicted for one row. vendor/product null = "not in KEV". */
export interface ArmPrediction {
  row_id: string;
  vendor: string | null;
  product: string | null;
  abstained?: boolean;       // the arm left the row to the owner (ask_owner / unresolved)
  used_ultra?: boolean;      // Ultra was needed for this row (adjudication or contested critique)
}

/** What resolveArm returns for one arm over a set of rows. */
export interface ArmOutput {
  predictions: ArmPrediction[];
  receipts: Receipt[];       // every model call this arm made for these rows
  notes?: string[];          // e.g. "time includes the Zetaris queries of the full pipeline"
}

/** Injected by the integration step: run one arm over the given rows. */
export type ResolveArm = (arm: ArmName, rows: InventoryRow[]) => Promise<ArmOutput>;

/** Thrown by a wiring that cannot run an arm (not wired yet, or no models in sample mode). */
export class ArmUnavailableError extends Error {
  arm: string;
  constructor(arm: string, message: string) {
    super(message);
    this.name = "ArmUnavailableError";
    this.arm = arm;
  }
}

export type RowOutcome =
  | "match_ok"        // answer is a KEV product; predicted vendor + an accepted spelling
  | "none_ok"         // answer none; predicted null
  | "none_abstained"  // answer none; the arm abstained (null). Correct under the scoring rule, flagged
  | "wrong_match"     // answer is a KEV product; predicted a different vendor or product
  | "missed"          // answer is a KEV product; predicted null
  | "abstained"       // answer is a KEV product; the arm abstained
  | "false_match"     // answer none; predicted a KEV product (a look-alike accepted)
  | "missing";        // the arm returned no prediction for the row

export interface RowScore {
  row_id: string;
  outcome: RowOutcome;
  correct: boolean;
  predicted: { vendor: string | null; product: string | null };
  expected: { vendor: string | null; products: string[]; none: boolean };
  used_ultra: boolean;
  lookalike: boolean;
}

export interface ArmMetrics {
  rows: number;                 // rows scored
  correct: number;
  accuracy: number | null;      // correct / rows
  correct_strict: number;       // abstentions counted wrong
  accuracy_strict: number | null;
  kev_rows: number;             // answer is a KEV product
  kev_matched: number;          // ... and the arm found it
  none_rows: number;            // answer is none
  none_rejected: number;        // ... and the arm predicted null (look-alike / none rejection)
  lookalike_rows: number;       // none rows tagged "look-alike" in the notes
  lookalike_rejected: number;
  abstained: number;
  missing: number;
  wrong_match: number;
  false_match: number;
  missed: number;
  ultra_rows: number;           // rows that needed Ultra
  ultra_share: number | null;   // ultra_rows / rows
  calls: number;                // model calls (receipts)
  calls_by_model: Record<string, number>;
  ultra_calls: number;
  call_errors: number;
  prompt_tokens: number;
  completion_tokens: number;
  tokens: number;
  time_ms: number;
}

export interface ArmResult {
  arm: ArmName;
  status: "ok" | "unavailable" | "error";
  message?: string;
  notes: string[];
  metrics: ArmMetrics | null;
  rows: RowScore[];             // per-row outcomes (kept out of stdout)
  extra_predictions: string[];  // row_ids predicted that were not asked for
}

export interface EvalResult {
  set: EvalSet;
  final: boolean;
  generated_at: string;         // ISO
  labels_source: string;        // base name only
  rows_evaluated: number;
  sealed_rows_excluded: number; // dev set: labelled rows withheld because they are test rows
  unlabelled_rows: string[];    // dev set: inventory row ids with no usable label (ids only)
  rows_without_inventory: string[]; // dev set: labelled row ids missing from the inventory (skipped)
  label_issues: SheetIssue[];
  software_mismatches: string[]; // row ids where the sheet's software differs from the inventory's
  arms: ArmResult[];
  baseline_model?: ModelKey;
}
