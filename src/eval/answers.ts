// Answer sheets: CSV with the columns row_id, software, kev_vendor, kev_products (";"-separated spellings), notes.
// "none" in kev_products means the product is not in KEV. Header spellings are matched loosely.
import { parseCsvObjects } from "./csv.ts";
import type { KevPair } from "../contracts.ts";
import type { AnswerRow, AnswerSheet, SheetIssue } from "./types.ts";

export const ANSWER_COLUMNS = ["row_id", "software", "kev_vendor", "kev_products", "notes"] as const;

const ALIASES: Record<string, string[]> = {
  row_id: ["rowid", "id", "row", "row_no", "row_number"],
  software: ["software_string", "raw", "inventory", "software_name", "item"],
  kev_vendor: ["vendor", "vendorproject", "vendor_project", "kev_vendorproject", "kev_vendor_project", "kev_vendors"],
  kev_products: ["kev_product", "products", "product", "kev_product_spellings", "spellings"],
  notes: ["note", "comments", "comment", "remarks"],
};

const NONE_WORDS = new Set(["none", "null", "nil", "n/a", "na", "no match", "not in kev", "not listed", "-", "–", "—"]);

/** Case-, space- and width-insensitive form used for every name comparison. */
export function normName(s: string): string {
  return s.normalize("NFKC").replace(/[​-‍﻿]/g, "").toLowerCase().replace(/\s+/g, "");
}

/** Canonical row id: trimmed and upper-cased ("r01 " -> "R01"). Leading zeros are kept. */
export function canonRowId(s: string): string {
  return s.trim().toUpperCase();
}

function noneForm(s: string): string {
  return s.normalize("NFKC").trim().toLowerCase().replace(/\s+/g, " ").replace(/[?.!]+$/, "").trim();
}

export function isNoneWord(s: string): boolean {
  return NONE_WORDS.has(noneForm(s));
}

// A cell that opens like a "none" answer: none, null, nil, n/a, "no match"/"no kev", "not in/on/listed/kev...",
// or a dash followed by a space. Narrow on purpose (no KEV name starts like this); the KEV-name check catches the rest.
const NONE_PREFIX = /^(?:(?:none|null|nil|n\/a|na|no (?:match|kev|entry)|not (?:in|on|listed|applicable|kev|found))(?![\p{L}\p{N}_])|[-–—] )/u;

/**
 * True for a cell that starts with a "none" word but carries extra text ("none (cloud service)", "None - SaaS",
 * "Not on KEV"). Such a cell is ambiguous: comments belong in the notes column.
 */
export function isNoneWithExtraText(s: string): boolean {
  const t = noneForm(s);
  return !NONE_WORDS.has(t) && NONE_PREFIX.test(t);
}

const NONE_EXTRA_TEXT = "'none' with extra text; put comments in the notes column";

function splitSpellings(s: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const part of s.split(";")) {
    const t = part.trim();
    if (t === "" || seen.has(normName(t))) continue;
    seen.add(normName(t));
    out.push(t);
  }
  return out;
}

/** A comparable key for an answer: "none", or the vendor set and product set. */
export function answerKey(a: AnswerRow): string {
  if (a.is_none) return "none";
  const v = a.kev_vendors.map(normName).sort().join(";");
  const p = a.kev_products.map(normName).sort().join(";");
  return `${v}|${p}`;
}

/**
 * Parses an answer sheet. Throws if a required column is missing. Rows that cannot be scored
 * (blank answer, product without vendor, conflicting duplicates) are left out and listed in `issues`.
 */
export function parseAnswerSheet(text: string, source = "answers"): AnswerSheet {
  const { header, rows } = parseCsvObjects(text, ALIASES);
  const missing = ["row_id", "kev_vendor", "kev_products"].filter((c) => !header.includes(c));
  if (missing.length > 0) {
    throw new Error(
      `${source}: missing column(s) ${missing.join(", ")}; expected the columns ${ANSWER_COLUMNS.join(", ")}`,
    );
  }
  const issues: SheetIssue[] = [];
  const parsed: AnswerRow[] = [];
  for (const { line, values } of rows) {
    const allBlank = Object.values(values).every((v) => v.trim() === "");
    if (allBlank) continue;
    const rowId = canonRowId(values.row_id ?? "");
    if (rowId === "") { issues.push({ row_id: null, line, problem: "missing row_id" }); continue; }
    const productsRaw = (values.kev_products ?? "").trim();
    const vendorRaw = (values.kev_vendor ?? "").trim();
    const notes = (values.notes ?? "").trim();
    const base = {
      row_id: rowId,
      software: (values.software ?? "").trim(),
      notes,
      unsure: /\b(unsure|not sure|uncertain)\b/i.test(notes),
      lookalike: /look[\s-]?alike/i.test(notes),
      line,
    };
    const productIsNone = productsRaw !== "" && isNoneWord(productsRaw);
    const vendorSaysNone = productsRaw === "" && vendorRaw !== "" && isNoneWord(vendorRaw) && !/^[-–—]$/.test(vendorRaw);
    if (productIsNone || vendorSaysNone) {
      parsed.push({ ...base, kev_vendor: null, kev_vendors: [], kev_products: [], is_none: true });
      continue;
    }
    // Not a clean "none": a none word with extra text in either answer column ("none (cloud service)",
    // "Not on KEV") is ambiguous, so the row is left unlabelled (fail closed) instead of becoming a KEV name.
    const noneExtra = [
      splitSpellings(productsRaw).some(isNoneWithExtraText) ? "kev_products" : "",
      splitSpellings(vendorRaw).some(isNoneWithExtraText) ? "kev_vendor" : "",
    ].filter(Boolean);
    if (noneExtra.length > 0) {
      issues.push({ row_id: rowId, line, problem: `${noneExtra.join(" and ")}: ${NONE_EXTRA_TEXT}` });
      continue;
    }
    if (productsRaw === "") { issues.push({ row_id: rowId, line, problem: "blank answer (no product and no 'none')" }); continue; }
    const products = splitSpellings(productsRaw);
    if (products.some(isNoneWord)) {
      issues.push({ row_id: rowId, line, problem: "kev_products mixes 'none' with product names" });
      continue;
    }
    const vendors = splitSpellings(vendorRaw).filter((v) => !isNoneWord(v));
    if (vendors.length === 0) {
      issues.push({ row_id: rowId, line, problem: "a KEV product is given without a KEV vendor" });
      continue;
    }
    parsed.push({ ...base, kev_vendor: vendors[0], kev_vendors: vendors, kev_products: products, is_none: false });
  }

  // Duplicates: identical answers keep the first; conflicting answers drop the row (fail closed).
  const byId = new Map<string, AnswerRow>();
  const conflicted = new Set<string>();
  for (const a of parsed) {
    const prev = byId.get(a.row_id);
    if (!prev) { byId.set(a.row_id, a); continue; }
    if (answerKey(prev) === answerKey(a)) {
      issues.push({ row_id: a.row_id, line: a.line, problem: `duplicate of line ${prev.line} (identical; ignored)` });
    } else {
      issues.push({ row_id: a.row_id, line: a.line, problem: `conflicts with line ${prev.line}; row left unlabelled` });
      conflicted.add(a.row_id);
    }
  }
  for (const id of conflicted) byId.delete(id);
  return { source, rows: [...byId.values()], issues };
}

function quoteList(names: string[]): string {
  return names.map((n) => `'${n}'`).join(", ");
}

/**
 * Checks every answer name against the KEV catalogue's (vendor, product) pairs, compared as in scoring.
 * A vendor that is not a KEV vendor, or a product spelling that is not a KEV product of one of the row's
 * vendors (a typo, or a comment typed into an answer cell), is a sheet issue and the row is left unlabelled
 * (fail closed). "none" rows pass. Throws when the KEV list is empty, since nothing could be checked.
 */
export function checkAnswersAgainstKev(sheet: AnswerSheet, pairs: KevPair[]): AnswerSheet {
  const productsByVendor = new Map<string, Set<string>>();
  for (const p of pairs) {
    const v = normName(p.vendor ?? "");
    const prod = normName(p.product ?? "");
    if (v === "" || prod === "") continue;
    let set = productsByVendor.get(v);
    if (!set) { set = new Set(); productsByVendor.set(v, set); }
    set.add(prod);
  }
  if (productsByVendor.size === 0) throw new Error("the KEV list is empty, so the answer names cannot be checked");
  const issues: SheetIssue[] = [...sheet.issues];
  const rows: AnswerRow[] = [];
  for (const a of sheet.rows) {
    if (a.is_none) { rows.push(a); continue; }
    const badVendors = a.kev_vendors.filter((v) => !productsByVendor.has(normName(v)));
    const badProducts = a.kev_products.filter(
      (p) => !a.kev_vendors.some((v) => productsByVendor.get(normName(v))?.has(normName(p))),
    );
    if (badVendors.length === 0 && badProducts.length === 0) { rows.push(a); continue; }
    const parts: string[] = [];
    if (badVendors.length > 0) parts.push(`kev_vendor ${quoteList(badVendors)} is not a KEV vendor`);
    if (badProducts.length > 0) {
      parts.push(`kev_products ${quoteList(badProducts)} ${badProducts.length === 1 ? "is not a KEV product" : "are not KEV products"} of ${quoteList(a.kev_vendors)}`);
    }
    issues.push({ row_id: a.row_id, line: a.line, problem: `${parts.join("; ")}; copy the names exactly from KEV (row left unlabelled)` });
  }
  return { source: sheet.source, rows, issues };
}
