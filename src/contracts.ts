// Shared interfaces for every module. Owner: the controller. Builders must not edit this file;
// request changes in your report instead. Plain type stripping rules apply (no enums, no parameter properties).

export const MODELS = {
  bolt: "nvidia/nemotron-3.5-bolt-e4b",
  lightning: "nvidia/nemotron-3.5-lightning-30b-a3b",
  ultra: "nvidia/nemotron-3-ultra-550b-a55b",
} as const;
export type ModelKey = keyof typeof MODELS;
export type ModelId = (typeof MODELS)[ModelKey];

export type Mode = "live" | "sample";
export type Decision = "patch_now" | "this_cycle" | "monitor" | "ask_owner";
export type ProductType =
  | "server" | "network_appliance" | "client" | "cloud_service" | "library" | "os" | "unknown";
export type TraceStatus = "ok" | "error" | "fallback" | "blocked" | "sent_back";

export interface Policy {
  epss_this_cycle: number;          // non-KEV CVE affecting the version, EPSS >= this -> this_cycle
  epss_this_cycle_internet: number; // same, for internet-facing assets
  sla_days: { patch_now: number; this_cycle: number; monitor_review: number };
  rubric_auto_min: number;          // rubric total below this -> ask_owner (autonomy L1)
  max_critic_rounds: number;        // send-back rounds before ask_owner
}
export const DEFAULT_POLICY: Policy = {
  epss_this_cycle: 0.1,
  epss_this_cycle_internet: 0.05,
  sla_days: { patch_now: 7, this_cycle: 30, monitor_review: 90 },
  rubric_auto_min: 7,
  max_critic_rounds: 2,
};

// ---------- data ----------
export interface InventoryRow {
  row_id: string; asset_id: string; asset_name: string; asset_type: string;
  internet_facing: boolean; owner_team: string; software: string;
}
export interface KevPair { vendor: string; product: string; }
export interface KevEntry {
  cve_id: string; vendor: string; product: string; vulnerability_name: string;
  date_added: string; due_date: string; ransomware_use: string; required_action: string;
  short_description: string; notes: string; catalog_version: string;
}
export interface EpssScore { cve_id: string; epss: number; percentile: number; score_date: string; }
export interface NvdRange {
  cve_id: string; criteria: string; vulnerable: boolean;
  version_start_including?: string; version_start_excluding?: string;
  version_end_including?: string; version_end_excluding?: string;
}
export interface NvdProductHit { cve_id: string; published: string; ranges: NvdRange[]; }

// ---------- resolution ----------
export interface ParsedSoftware {
  raw: string; vendor_hint: string | null; product_hint: string; version: string | null;
  product_type: ProductType; tokens: string[];
}
export interface Candidate extends KevPair { family: string; score: number; reason: string; }
export interface Receipt {
  call_id: string; agent: string; requested_model: string; response_model: string | null;
  routed_model: string | null; receipt_id: string | null; latency_ms: number;
  prompt_tokens?: number; completion_tokens?: number; status: "ok" | "error"; error?: string;
}
export interface JurorVote {
  row_id: string; juror: ModelKey | "normaliser";
  vendor: string | null; product: string | null; product_type?: ProductType;
  confidence: number; receipt_id?: string | null;
}
export interface Resolution {
  row_id: string; status: "matched" | "no_match" | "unresolved";
  vendor: string | null; product: string | null; family: string | null;
  version: string | null; product_type: ProductType;
  votes: JurorVote[]; adjudicated_by: ModelKey | "critic" | "rules" | null; confidence: number;
}
export interface Rubric { accuracy: number; appropriateness: number; actionability: number; total: number; } // each 0-3
export interface CriticVerdict {
  row_id: string; verdict: "approve" | "send_back" | "ask_owner";
  reasons: string[]; rubric: Rubric; round: number;
}

// ---------- output ----------
export interface Evidence {
  source: "zetaris:inventory" | "zetaris:kev" | "zetaris:epss" | "zetaris:nvd" | "world_model" | "agent";
  query: string; sql_hash?: string; field: string; value: string; as_of?: string; live: boolean;
}
export interface PatchLine {
  row_id: string; asset_id: string; asset_name: string; internet_facing: boolean; software: string;
  resolution: Resolution; decision: Decision; target_date: string | null;
  kev: { cves: KevEntry[]; earliest_due: string | null; overdue_days: number | null } | null;
  epss: { max: number; cve_id: string; percentile: number } | null;
  evidence: Evidence[]; critic: CriticVerdict | null; verified: boolean; verifier_notes: string[];
  why: string;
}
export interface OwnerQuestion { row_id: string; asset_name: string; question: string; reason: string; }
export interface RunManifest {
  engine: "world-model" | "h-mem"; engine_source: string;
  sources: { name: string; object: string; live: boolean; as_of?: string }[];
  models: typeof MODELS; helpers_live: string[]; helpers_dormant: string[]; policy: Policy;
}
export interface RunRequest {
  run_id?: string; inventory?: InventoryRow[]; row_ids?: string[];
  sample_mode?: boolean; policy?: Partial<Policy>;
}
export interface RunResponse {
  run_id: string; mode: Mode; status: "success" | "partial" | "error";
  started_at: string; finished_at: string; as_of: string; timing_ms: Record<string, number>;
  summary: Record<Decision, number>; lines: PatchLine[]; owner_questions: OwnerQuestion[];
  receipts: Receipt[]; trace_file: string; report_file: string | null; manifest: RunManifest;
  error?: { type: string; message: string; recoverable: boolean };
}
export interface TraceEvent {
  ts: string; run_id: string; agent: string; action: string;
  input_summary?: string; output_summary?: string; target_agent?: string;
  model?: string; routed_model?: string | null; receipt_id?: string | null; latency_ms?: number;
  confidence?: number; retry_count?: number; status: TraceStatus; details?: Record<string, unknown>;
}

// ---------- seams (dependency injection; live and sample implementations) ----------
export interface Clock { now(): Date; }
export interface ChatRequest {
  model: ModelKey; agent: string; system?: string; user: string; max_tokens?: number; json?: boolean;
}
export interface ChatResult { text: string; json: unknown | null; receipt: Receipt; }
export interface Llm { chat(req: ChatRequest): Promise<ChatResult>; }
export interface Queries {
  inventory(): Promise<InventoryRow[]>;
  kevPairs(): Promise<KevPair[]>;
  kevByProducts(pairs: KevPair[]): Promise<KevEntry[]>;
  kevVerify(cveIds: string[]): Promise<KevEntry[]>;   // live, never cached
  epss(cveIds: string[]): Promise<EpssScore[]>;       // batches of <=100 CVEs
  epssVerify(cveIds: string[]): Promise<EpssScore[]>; // live, never cached
  nvdCves(cveIds: string[]): Promise<NvdRange[]>;
  nvdProduct(cpeVendor: string, cpeProduct: string): Promise<NvdProductHit[]>; // may be dormant
}
export interface Tracer {
  readonly run_id: string; readonly file: string;
  emit(e: Omit<TraceEvent, "ts" | "run_id">): void;
}
export interface Deps {
  mode: Mode; clock: Clock; llm: Llm | null; queries: Queries; tracer: Tracer; policy: Policy;
}
