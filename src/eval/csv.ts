// A small RFC 4180 CSV parser: quoted fields with commas, newlines and doubled quotes; CRLF, LF or CR;
// a leading BOM; comma, tab or semicolon delimiters (detected from the header line). No dependencies.

export class CsvError extends Error {
  line: number;
  constructor(message: string, line: number) {
    super(`${message} (line ${line})`);
    this.name = "CsvError";
    this.line = line;
  }
}

export interface CsvRecord { line: number; fields: string[]; }

/** Picks the delimiter from the first line: the most frequent of comma, tab, semicolon outside quotes. */
export function detectDelimiter(text: string): string {
  const counts: Record<string, number> = { ",": 0, "\t": 0, ";": 0 };
  let inQuotes = false;
  for (const ch of stripBom(text)) {
    if (ch === '"') inQuotes = !inQuotes;
    else if (!inQuotes && (ch === "\n" || ch === "\r")) break;
    else if (!inQuotes && ch in counts) counts[ch]++;
  }
  let best = ",";
  for (const d of ["\t", ";"]) if (counts[d] > counts[best]) best = d;
  return best;
}

function stripBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

/**
 * Parses CSV text into records. Each record keeps the 1-based line it started on.
 * Lines that are completely empty are skipped. An unterminated quote throws CsvError.
 */
export function parseCsv(input: string, opts: { delimiter?: string } = {}): CsvRecord[] {
  const text = stripBom(input);
  const delim = opts.delimiter ?? detectDelimiter(text);
  const out: CsvRecord[] = [];
  let fields: string[] = [];
  let field = "";
  let inQuotes = false;
  let quotedField = false;   // the current field started with a quote
  let line = 1;
  let recordLine = 1;
  let quoteOpenLine = 1;

  const endField = () => { fields.push(field); field = ""; quotedField = false; };
  const endRecord = () => {
    endField();
    const empty = fields.length === 1 && fields[0] === "";
    if (!empty) out.push({ line: recordLine, fields });
    fields = [];
  };

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else {
        if (ch === "\n" || (ch === "\r" && text[i + 1] !== "\n")) line++;
        field += ch;
      }
      continue;
    }
    if (ch === '"') {
      if (field === "" && !quotedField) { inQuotes = true; quotedField = true; quoteOpenLine = line; }
      else field += ch; // a stray quote inside an unquoted field is kept literally
    } else if (ch === delim) {
      endField();
    } else if (ch === "\r" || ch === "\n") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      endRecord();
      line++;
      recordLine = line;
    } else {
      field += ch;
    }
  }
  if (inQuotes) throw new CsvError("unterminated quoted field", quoteOpenLine);
  if (field !== "" || fields.length > 0 || quotedField) endRecord();
  return out;
}

/** Lower-cases a header and reduces it to [a-z0-9_]; "Software (copy it from the row)" -> "software". */
export function normaliseHeader(h: string): string {
  return h
    .replace(/\(.*?\)/g, " ")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

/**
 * Parses CSV with a header row into objects keyed by canonical column names.
 * `aliases` maps a canonical name to the header spellings that mean it (already normalised).
 * Unknown columns are kept under their normalised header.
 */
export function parseCsvObjects(
  input: string,
  aliases: Record<string, string[]> = {},
): { header: string[]; rows: { line: number; values: Record<string, string> }[] } {
  const records = parseCsv(input);
  if (records.length === 0) return { header: [], rows: [] };
  const lookup = new Map<string, string>();
  for (const [canon, names] of Object.entries(aliases)) {
    lookup.set(canon, canon);
    for (const n of names) lookup.set(n, canon);
  }
  const header = records[0].fields.map((h) => {
    const n = normaliseHeader(h);
    return lookup.get(n) ?? n;
  });
  const rows = records.slice(1).map((r) => {
    const values: Record<string, string> = {};
    header.forEach((h, idx) => {
      if (h === "" || Object.hasOwn(values, h)) return; // first column wins on duplicates
      values[h] = r.fields[idx] ?? "";
    });
    return { line: r.line, values };
  });
  return { header, rows };
}

/** Escapes a value for a Markdown table cell. */
export function mdCell(v: unknown): string {
  const s = v === null || v === undefined ? "" : String(v);
  return s.replace(/\r?\n|\r/g, " ").replace(/\|/g, "\\|").trim();
}
