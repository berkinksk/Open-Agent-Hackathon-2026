// Environment configuration. Reads process.env (or an injected env), validates it,
// and reports problems by variable NAME only. Values of secrets are never printed.
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Mode } from "./contracts.ts";

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const DEFAULT_INVENTORY_URL =
  "https://raw.githubusercontent.com/berkinksk/exposureledger/main/data/inventory.json";
export const DEFAULT_PREFIX = "EL_";
export const DEFAULT_PORT = 8000;

/** Variables whose values must never appear in output. */
export const SECRET_VARS = ["ZETARIS_API_KEY", "METERLESS_RUNTIME_TOKEN"] as const;

export interface AppConfig {
  zetaris: { restUrl: string; orgId: string; apiKey: string };
  meterless: { baseUrl: string; token: string };
  sampleMode: boolean;
  port: number;
  prefix: string;       // "EL_" by default; databases use it as-is, tables/containers in lowercase
  inventoryUrl: string;
}

export interface ConfigCheck {
  ok: boolean;
  missing: string[];  // names of required variables that are unset or empty
  invalid: string[];  // "NAME: reason" (never the value)
}

export class ConfigError extends Error {
  readonly missing: string[];
  readonly invalid: string[];
  constructor(message: string, missing: string[] = [], invalid: string[] = []) {
    super(message);
    this.name = "ConfigError";
    this.missing = missing;
    this.invalid = invalid;
  }
}

type Env = Record<string, string | undefined>;

function str(env: Env, name: string): string {
  return (env[name] ?? "").trim();
}

export function parseBool(v: string | undefined | null): boolean {
  return /^(1|true|yes|y|on)$/i.test((v ?? "").trim());
}

/** Load config from env without validating. Missing values become "". */
export function loadConfig(env: Env = process.env): AppConfig {
  const portRaw = str(env, "PORT");
  return {
    zetaris: {
      restUrl: str(env, "ZETARIS_REST_URL").replace(/\/+$/, ""),
      orgId: str(env, "ZETARIS_ORG_ID"),
      apiKey: str(env, "ZETARIS_API_KEY"),
    },
    meterless: {
      baseUrl: str(env, "METERLESS_BASE_URL").replace(/\/+$/, ""),
      token: str(env, "METERLESS_RUNTIME_TOKEN"),
    },
    sampleMode: parseBool(env.SAMPLE_MODE),
    port: portRaw === "" ? DEFAULT_PORT : Number(portRaw),
    prefix: str(env, "EL_PREFIX") || DEFAULT_PREFIX,
    inventoryUrl: str(env, "INVENTORY_URL") || DEFAULT_INVENTORY_URL,
  };
}

/** A prefix must keep every object inside the EL_ namespace: EL_, EL_T1_, EL_DEV_2_ ... */
export function isValidPrefix(p: string): boolean {
  return /^EL_([A-Z0-9]+_)*$/.test(p);
}

function isHttpUrl(u: string): boolean {
  try {
    const x = new URL(u);
    return x.protocol === "http:" || x.protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Validate for a purpose. "zetaris" = setup and queries; "live" = a full live run
 * (Zetaris + Nightshift); "sample" = nothing external is required.
 */
export function checkConfig(cfg: AppConfig, needs: Mode | "zetaris"): ConfigCheck {
  const missing: string[] = [];
  const invalid: string[] = [];
  const need = (name: string, value: string) => { if (!value) missing.push(name); };
  if (needs === "live" || needs === "zetaris") {
    need("ZETARIS_REST_URL", cfg.zetaris.restUrl);
    need("ZETARIS_ORG_ID", cfg.zetaris.orgId);
    need("ZETARIS_API_KEY", cfg.zetaris.apiKey);
    if (cfg.zetaris.restUrl && !isHttpUrl(cfg.zetaris.restUrl)) invalid.push("ZETARIS_REST_URL: not an http(s) URL");
  }
  if (needs === "live") {
    need("METERLESS_BASE_URL", cfg.meterless.baseUrl);
    need("METERLESS_RUNTIME_TOKEN", cfg.meterless.token);
    if (cfg.meterless.baseUrl && !isHttpUrl(cfg.meterless.baseUrl)) invalid.push("METERLESS_BASE_URL: not an http(s) URL");
  }
  if (!Number.isInteger(cfg.port) || cfg.port < 1 || cfg.port > 65535) invalid.push("PORT: must be an integer 1-65535");
  if (!isValidPrefix(cfg.prefix)) invalid.push("EL_PREFIX: must look like EL_ or EL_T1_ (uppercase, starts with EL_, ends with _)");
  if (!isHttpUrl(cfg.inventoryUrl)) invalid.push("INVENTORY_URL: not an http(s) URL");
  return { ok: missing.length === 0 && invalid.length === 0, missing, invalid };
}

/** Throw a ConfigError (names only) unless the config is usable for `needs`. */
export function requireConfig(cfg: AppConfig, needs: Mode | "zetaris"): AppConfig {
  const c = checkConfig(cfg, needs);
  if (!c.ok) {
    const parts: string[] = [];
    if (c.missing.length) parts.push(`missing: ${c.missing.join(", ")}`);
    if (c.invalid.length) parts.push(`invalid: ${c.invalid.join("; ")}`);
    throw new ConfigError(`configuration not usable for ${needs} mode (${parts.join(" | ")})`, c.missing, c.invalid);
  }
  return cfg;
}

/** A printable view of the config: URLs and flags shown, secrets reduced to set/unset. */
export function describeConfig(cfg: AppConfig): Record<string, string> {
  return {
    ZETARIS_REST_URL: cfg.zetaris.restUrl || "(unset)",
    ZETARIS_ORG_ID: cfg.zetaris.orgId || "(unset)",
    ZETARIS_API_KEY: cfg.zetaris.apiKey ? "(set, redacted)" : "(unset)",
    METERLESS_BASE_URL: cfg.meterless.baseUrl || "(unset)",
    METERLESS_RUNTIME_TOKEN: cfg.meterless.token ? "(set, redacted)" : "(unset)",
    SAMPLE_MODE: String(cfg.sampleMode),
    PORT: String(cfg.port),
    EL_PREFIX: cfg.prefix,
    INVENTORY_URL: cfg.inventoryUrl,
  };
}

/** Values that must be scrubbed from any log line (only non-trivial ones). */
export function secretValues(env: Env = process.env): string[] {
  return SECRET_VARS.map((n) => (env[n] ?? "").trim()).filter((v) => v.length >= 6);
}

/** Run ids become file names, so keep them to a safe alphabet. */
export function isSafeId(id: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/.test(id);
}

export function newRunId(now: Date = new Date()): string {
  const t = now.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z").replace("T", "-");
  const rand = Math.floor(Math.random() * 0xffff).toString(16).padStart(4, "0");
  return `run-${t}-${rand}`;
}
