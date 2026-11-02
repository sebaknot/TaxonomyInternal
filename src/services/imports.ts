import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { parse } from 'csv-parse/sync';
import ExcelJS from 'exceljs';
import type { AppContext } from '../context.js';
import { newId, randomToken } from '../lib/crypto.js';
import { audit } from './audit.js';
import { createClient, type ClientInput } from './clients.js';
import type { SessionUser } from './permissions.js';
import { encryptForUpload, decryptDownloaded } from './documents.js';
import crypto from 'node:crypto';

/** Client fields that an import can populate, with header aliases (TaxWise-style and common variants). */
export const IMPORT_FIELDS: { key: keyof ClientInput | 'first_name' | 'last_name' | 'skip'; label: string; required?: boolean; aliases: string[] }[] = [
  { key: 'skip', label: '— Ignore this column —', aliases: [] },
  { key: 'legal_name', label: 'Legal name (full)', aliases: ['name', 'legal name', 'full name', 'taxpayer name', 'client name', 'taxpayer'] },
  { key: 'first_name', label: 'First name (combined with last name)', aliases: ['first name', 'first', 'fname', 'taxpayer first name', 'tp first name', 'given name'] },
  { key: 'last_name', label: 'Last name (combined with first name)', aliases: ['last name', 'last', 'lname', 'taxpayer last name', 'tp last name', 'surname', 'family name'] },
  { key: 'preferred_name', label: 'Preferred name', aliases: ['preferred name', 'nickname', 'goes by'] },
  { key: 'ssn', label: 'SSN', aliases: ['ssn', 'social security', 'social security number', 'taxpayer ssn', 'tp ssn', 'ssn/itin', 'tin', 'itin'] },
  { key: 'dob', label: 'Date of birth', aliases: ['dob', 'date of birth', 'birth date', 'birthdate', 'taxpayer dob', 'tp dob'] },
  { key: 'phone', label: 'Phone', aliases: ['phone', 'phone number', 'telephone', 'cell', 'mobile', 'home phone', 'cell phone', 'day phone'] },
  { key: 'email', label: 'Email', aliases: ['email', 'e-mail', 'email address', 'taxpayer email'] },
  { key: 'address_line1', label: 'Address line 1', aliases: ['address', 'street', 'address 1', 'address line 1', 'street address', 'addr1', 'mailing address'] },
  { key: 'address_line2', label: 'Address line 2', aliases: ['address 2', 'address line 2', 'apt', 'unit', 'addr2', 'suite'] },
  { key: 'city', label: 'City', aliases: ['city', 'town'] },
  { key: 'state', label: 'State', aliases: ['state', 'st', 'province'] },
  { key: 'zip', label: 'ZIP', aliases: ['zip', 'zip code', 'zipcode', 'postal code', 'postal'] },
  { key: 'filing_status', label: 'Filing status', aliases: ['filing status', 'status', 'fs', 'filing'] },
  { key: 'spouse_name', label: 'Spouse name', aliases: ['spouse', 'spouse name', 'sp name', 'spouse full name'] },
  { key: 'spouse_ssn', label: 'Spouse SSN', aliases: ['spouse ssn', 'sp ssn', 'spouse social'] },
  { key: 'spouse_dob', label: 'Spouse date of birth', aliases: ['spouse dob', 'sp dob', 'spouse date of birth', 'spouse birth date'] },
  { key: 'source', label: 'Source', aliases: ['source', 'referral source', 'how heard', 'lead source', 'origin'] },
  { key: 'notes', label: 'Internal notes', aliases: ['notes', 'note', 'comments', 'remarks', 'memo'] },
  { key: 'client_since_year', label: 'Client since (year)', aliases: ['client since', 'since', 'first year', 'client since year', 'start year', 'year started'] },
  { key: 'tags', label: 'Tags (comma-separated)', aliases: ['tags', 'specialization', 'specializations', 'categories', 'tag'] },
];

const norm = (s: string) => s.toLowerCase().replace(/[_\-\.]/g, ' ').replace(/\s+/g, ' ').trim();

/** Suggests a mapping for each spreadsheet header. Exact alias matches win; otherwise unmapped. */
export function suggestMapping(headers: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  const used = new Set<string>();
  for (const h of headers) {
    const n = norm(h);
    let hit = IMPORT_FIELDS.find((f) => f.key !== 'skip' && f.aliases.some((a) => norm(a) === n));
    if (!hit) hit = IMPORT_FIELDS.find((f) => f.key !== 'skip' && f.aliases.some((a) => a.length > 3 && (n.includes(norm(a)) || norm(a).includes(n))));
    if (hit && !used.has(hit.key)) {
      out[h] = hit.key;
      used.add(hit.key);
    } else out[h] = 'skip';
  }
  return out;
}

export interface ParsedSheet {
  headers: string[];
  rows: Record<string, string>[];
}

function cellToString(v: unknown): string {
  if (v == null) return '';
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  if (typeof v === 'object') {
    const o = v as any;
    if (o.richText) return o.richText.map((r: any) => r.text).join('');
    if (o.text) return String(o.text);
    if (o.result != null) return cellToString(o.result);
    if (o.hyperlink) return String(o.text ?? o.hyperlink);
    return String(v);
  }
  return String(v);
}

/** Parses a CSV or XLSX from memory. XLSX goes through a private temp file (exceljs streams from disk). */
export async function parseSpreadsheet(content: Buffer, originalName: string): Promise<ParsedSheet> {
  const ext = path.extname(originalName).toLowerCase();
  if (ext === '.csv' || ext === '.txt' || ext === '.tsv') {
    const text = content.toString('utf8').replace(/^\uFEFF/, '');
    const records: string[][] = parse(text, { bom: true, skip_empty_lines: true, relax_column_count: true, delimiter: ext === '.tsv' ? '\t' : [',', ';', '\t'], trim: true });
    if (!records.length) throw new Error('The file is empty');
    const headers = records[0].map((h, i) => (h?.trim() ? h.trim() : `Column ${i + 1}`));
    const rows = records.slice(1).map((r) => Object.fromEntries(headers.map((h, i) => [h, (r[i] ?? '').trim()])));
    return { headers, rows };
  }
  if (ext === '.xlsx' || ext === '.xlsm') {
    const wb = new ExcelJS.Workbook();
    const tmp = path.join(os.tmpdir(), `tx-import-${randomToken(8)}.xlsx`);
    fs.writeFileSync(tmp, content, { mode: 0o600 });
    try {
      await wb.xlsx.readFile(tmp);
    } finally {
      fs.rmSync(tmp, { force: true });
    }
    const ws = wb.worksheets[0];
    if (!ws) throw new Error('The workbook has no sheets');
    const headers: string[] = [];
    const rows: Record<string, string>[] = [];
    ws.eachRow((row, rowNumber) => {
      const values: string[] = [];
      for (let c = 1; c <= row.cellCount; c++) values[c - 1] = cellToString(row.getCell(c).value).trim();
      if (rowNumber === 1) {
        values.forEach((h, i) => headers.push(h || `Column ${i + 1}`));
        return;
      }
      if (values.every((v) => v === '')) return;
      rows.push(Object.fromEntries(headers.map((h, i) => [h, values[i] ?? ''])));
    });
    if (!headers.length) throw new Error('The sheet is empty');
    return { headers, rows };
  }
  if (ext === '.xls') throw new Error('Legacy .xls is not supported — save the file as .xlsx or .csv and try again.');
  throw new Error('Unsupported file type. Upload a .csv or .xlsx file.');
}

export interface ImportRow {
  id: string;
  created_by: string;
  original_filename: string;
  storage_path: string;
  data_key_enc: string;
  headers: string;
  row_count: number;
  mapping: string | null;
  status: string;
  summary: string | null;
  created_at: string;
  completed_at: string | null;
}

/** Stage an uploaded file: parse, store an encrypted copy in Storage, suggest a mapping. */
export async function stageImport(ctx: AppContext, content: Buffer, originalName: string, actor: SessionUser): Promise<{ record: ImportRow; sheet: ParsedSheet; suggested: Record<string, string> }> {
  const sheet = await parseSpreadsheet(content, originalName);
  const id = newId();
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const storagePath = `imports/${id}${path.extname(originalName).toLowerCase()}.bin`;
  const { ciphertext } = encryptForUpload(content, key, iv);
  await ctx.storage.put(storagePath, ciphertext);
  await ctx.db.run(
    'INSERT INTO imports (id, created_by, original_filename, storage_path, data_key_enc, headers, row_count) VALUES (?, ?, ?, ?, ?, ?, ?)',
    id,
    actor.id,
    path.basename(originalName),
    storagePath,
    ctx.cipher.encrypt(`${key.toString('base64')}:${iv.toString('base64')}`, `importkey:${id}`),
    JSON.stringify(sheet.headers),
    sheet.rows.length,
  );
  await audit(ctx, { actorType: 'user', actorId: actor.id, actorLabel: actor.email, action: 'import.stage', entityType: 'import', entityId: id, details: { filename: originalName, rows: sheet.rows.length } });
  return { record: (await getImport(ctx, id))!, sheet, suggested: suggestMapping(sheet.headers) };
}

export function getImport(ctx: AppContext, id: string) {
  return ctx.db.one<ImportRow>('SELECT * FROM imports WHERE id = ?', id);
}
export function listImports(ctx: AppContext) {
  return ctx.db.all<ImportRow & { creator: string }>('SELECT i.*, u.name creator FROM imports i JOIN users u ON u.id = i.created_by ORDER BY i.created_at DESC LIMIT 100');
}

export async function loadStagedSheet(ctx: AppContext, record: ImportRow): Promise<ParsedSheet> {
  if (record.status === 'completed') throw new Error('The staged file was removed after the import ran. Upload it again.');
  let ciphertext: Uint8Array;
  try {
    ciphertext = await ctx.storage.get(record.storage_path);
  } catch {
    throw new Error('The staged file is no longer available. Upload it again.');
  }
  const [k, i] = ctx.cipher.decrypt(record.data_key_enc, `importkey:${record.id}`).split(':');
  const content = decryptDownloaded(Buffer.from(ciphertext), Buffer.from(k, 'base64'), Buffer.from(i, 'base64'));
  return parseSpreadsheet(content, record.original_filename);
}

export interface ImportSummary {
  created: number;
  failed: number;
  errors: { row: number; message: string; name?: string }[];
}

/** Applies the mapping and creates one client per row. Failed rows are reported, never silently dropped. */
export async function runImport(ctx: AppContext, record: ImportRow, mapping: Record<string, string>, actor: SessionUser, ip?: string): Promise<ImportSummary> {
  const sheet = await loadStagedSheet(ctx, record);
  const summary: ImportSummary = { created: 0, failed: 0, errors: [] };
  const mappedKeys = new Set(Object.values(mapping).filter((k) => k !== 'skip'));
  if (!mappedKeys.has('legal_name') && !(mappedKeys.has('first_name') || mappedKeys.has('last_name'))) {
    throw new Error('Map a column to "Legal name" (or First name / Last name) before importing.');
  }
  for (let i = 0; i < sheet.rows.length; i++) {
    const row = sheet.rows[i];
    const rowNo = i + 2; // 1-based, after the header row
    const input: Record<string, unknown> = {};
    let first = '';
    let last = '';
    let rowError: string | null = null;
    for (const [header, key] of Object.entries(mapping)) {
      if (key === 'skip' || !(header in row)) continue;
      const value = row[header];
      if (key === 'first_name') first = value;
      else if (key === 'last_name') last = value;
      else if (key === 'tags') input.tags = value.split(/[,;|]/).map((t) => t.trim()).filter(Boolean);
      else if (key === 'client_since_year') {
        const y = parseInt(value, 10);
        if (value && !Number.isFinite(y)) rowError = `Invalid "client since" year: ${value}`;
        input.client_since_year = value ? y : null;
      } else input[key] = value;
    }
    if (!input.legal_name) input.legal_name = [first, last].filter(Boolean).join(' ').trim();
    try {
      if (rowError) throw new Error(rowError);
      if (!String(input.legal_name || '').trim()) throw new Error('Missing required field: legal name');
      await createClient(ctx, input as unknown as ClientInput, { type: 'user', id: actor.id, label: actor.email, ip }, 'import');
      summary.created++;
    } catch (err) {
      summary.failed++;
      summary.errors.push({ row: rowNo, message: (err as Error).message, name: String(input.legal_name || '') });
    }
  }
  await ctx.db.run("UPDATE imports SET mapping = ?, status = 'completed', summary = ?, completed_at = now() WHERE id = ?", JSON.stringify(mapping), JSON.stringify(summary), record.id);
  // The staged file (with SSNs) is not needed after a run; remove it from storage.
  try {
    await ctx.storage.remove([record.storage_path]);
  } catch (err) {
    console.error('import cleanup: storage remove failed', err);
  }
  await audit(ctx, { actorType: 'user', actorId: actor.id, actorLabel: actor.email, action: 'import.run', entityType: 'import', entityId: record.id, details: { created: summary.created, failed: summary.failed }, ip });
  return summary;
}
