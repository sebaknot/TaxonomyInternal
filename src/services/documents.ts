import fs from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import crypto from 'node:crypto';
import type { AppContext } from '../context.js';
import { newId, randomToken } from '../lib/crypto.js';
import { audit } from './audit.js';
import type { Actor } from './clients.js';
import { DOCUMENT_CATEGORIES, DOCUMENT_STATUSES, ALLOWED_UPLOAD_EXTENSIONS, MAX_UPLOAD_BYTES, type DocumentStatus } from '../lib/constants.js';

export interface DocumentRow {
  id: string;
  client_id: string;
  tax_year: number;
  category: string;
  title: string;
  status: DocumentStatus;
  rejection_reason: string | null;
  status_set_by: string | null;
  status_set_at: string | null;
  created_at: string;
  updated_at: string;
}
export interface VersionRow {
  id: string;
  document_id: string;
  version_no: number;
  original_filename: string;
  stored_name: string;
  size_bytes: number;
  mime_type: string | null;
  sha256: string;
  iv: string;
  auth_tag: string;
  uploaded_by_type: string;
  uploaded_by_id: string | null;
  uploaded_by_label: string;
  uploaded_at: string;
}

export function validateUploadName(originalName: string): string | null {
  const ext = path.extname(originalName).toLowerCase();
  if (!ALLOWED_UPLOAD_EXTENSIONS.has(ext)) return `File type "${ext || 'unknown'}" is not allowed.`;
  return null;
}
export function safeFilename(name: string): string {
  return path.basename(name).replace(/[\r\n"\\]/g, '_').slice(0, 200) || 'file';
}

/** Encrypts the temp file into the vault; returns stored metadata. The plaintext temp file is removed. */
async function storeEncrypted(ctx: AppContext, tempPath: string): Promise<{ storedName: string; iv: string; tag: string; sha256: string; size: number }> {
  const storedName = randomToken(24) + '.bin';
  const dest = path.join(ctx.uploadsDir, storedName);
  const { iv, cipher } = ctx.cipher.fileEncryptor();
  const hash = crypto.createHash('sha256');
  let size = 0;
  const src = fs.createReadStream(tempPath);
  src.on('data', (chunk) => {
    hash.update(chunk);
    size += chunk.length;
  });
  try {
    await pipeline(src, cipher, fs.createWriteStream(dest, { mode: 0o600 }));
  } finally {
    fs.rmSync(tempPath, { force: true });
  }
  if (size > MAX_UPLOAD_BYTES) {
    fs.rmSync(dest, { force: true });
    throw new Error('File too large');
  }
  return { storedName, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), sha256: hash.digest('hex'), size };
}

export interface UploadInput {
  clientId: string;
  taxYear: number;
  category: string;
  tempPath: string;
  originalFilename: string;
  mimeType?: string | null;
  /** When set, adds a new version to this existing document instead of creating one. */
  replaceDocumentId?: string | null;
  title?: string | null;
}

export async function uploadDocument(ctx: AppContext, input: UploadInput, actor: Actor): Promise<{ document: DocumentRow; version: VersionRow }> {
  if (!(DOCUMENT_CATEGORIES as readonly string[]).includes(input.category)) throw new Error('Invalid category');
  if (!Number.isInteger(input.taxYear) || input.taxYear < 1990 || input.taxYear > 2100) throw new Error('Invalid tax year');
  const nameErr = validateUploadName(input.originalFilename);
  if (nameErr) throw new Error(nameErr);
  const original = safeFilename(input.originalFilename);
  const stored = await storeEncrypted(ctx, input.tempPath);

  let docId = input.replaceDocumentId ?? null;
  let versionNo = 1;
  const versionId = newId();
  ctx.db.transaction(() => {
    if (docId) {
      const existing = getDocument(ctx, docId);
      if (!existing || existing.client_id !== input.clientId) throw new Error('Document to replace not found');
      const max = ctx.db.prepare('SELECT MAX(version_no) m FROM document_versions WHERE document_id = ?').get(docId) as { m: number | null };
      versionNo = (max.m ?? 0) + 1;
      ctx.db.prepare("UPDATE documents SET updated_at = datetime('now') WHERE id = ?").run(docId);
    } else {
      docId = newId();
      ctx.db
        .prepare('INSERT INTO documents (id, client_id, tax_year, category, title) VALUES (?, ?, ?, ?, ?)')
        .run(docId, input.clientId, input.taxYear, input.category, (input.title || '').trim() || original);
    }
    ctx.db
      .prepare(
        `INSERT INTO document_versions (id, document_id, version_no, original_filename, stored_name, size_bytes, mime_type, sha256, iv, auth_tag, uploaded_by_type, uploaded_by_id, uploaded_by_label)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(versionId, docId, versionNo, original, stored.storedName, stored.size, input.mimeType ?? null, stored.sha256, stored.iv, stored.tag, actor.type === 'client' ? 'client' : 'user', actor.id ?? null, actor.label);
  })();
  audit(ctx, {
    actorType: actor.type,
    actorId: actor.id,
    actorLabel: actor.label,
    action: versionNo > 1 ? 'document.new_version' : 'document.upload',
    entityType: 'document',
    entityId: docId!,
    clientId: input.clientId,
    details: { filename: original, tax_year: input.taxYear, category: input.category, version: versionNo, size: stored.size },
    ip: actor.ip,
    userAgent: actor.userAgent,
  });
  return { document: getDocument(ctx, docId!)!, version: ctx.db.prepare('SELECT * FROM document_versions WHERE id = ?').get(versionId) as VersionRow };
}

export function getDocument(ctx: AppContext, id: string): DocumentRow | undefined {
  return ctx.db.prepare('SELECT * FROM documents WHERE id = ?').get(id) as DocumentRow | undefined;
}
export function getVersion(ctx: AppContext, id: string): VersionRow | undefined {
  return ctx.db.prepare('SELECT * FROM document_versions WHERE id = ?').get(id) as VersionRow | undefined;
}
export function listVersions(ctx: AppContext, documentId: string): VersionRow[] {
  return ctx.db.prepare('SELECT * FROM document_versions WHERE document_id = ? ORDER BY version_no DESC').all(documentId) as VersionRow[];
}

export interface VaultDoc extends DocumentRow {
  versions: VersionRow[];
  latest: VersionRow;
}
/** Documents organized by tax year (desc) then category (spec order). */
export function clientVault(ctx: AppContext, clientId: string): { year: number; categories: { category: string; documents: VaultDoc[] }[] }[] {
  const docs = ctx.db.prepare('SELECT * FROM documents WHERE client_id = ? ORDER BY tax_year DESC, created_at').all(clientId) as DocumentRow[];
  const byYear = new Map<number, Map<string, VaultDoc[]>>();
  for (const d of docs) {
    const versions = listVersions(ctx, d.id);
    if (!versions.length) continue;
    if (!byYear.has(d.tax_year)) byYear.set(d.tax_year, new Map());
    const cats = byYear.get(d.tax_year)!;
    if (!cats.has(d.category)) cats.set(d.category, []);
    cats.get(d.category)!.push({ ...d, versions, latest: versions[0] });
  }
  return [...byYear.entries()]
    .sort((a, b) => b[0] - a[0])
    .map(([year, cats]) => ({
      year,
      categories: DOCUMENT_CATEGORIES.filter((c) => cats.has(c)).map((c) => ({ category: c, documents: cats.get(c)! })),
    }));
}

export function setDocumentStatus(ctx: AppContext, doc: DocumentRow, status: string, reason: string | null, actor: Actor) {
  if (!(DOCUMENT_STATUSES as readonly string[]).includes(status)) throw new Error('Invalid status');
  if (status === 'rejected' && !(reason || '').trim()) throw new Error('A reason is required when rejecting a document');
  ctx.db
    .prepare("UPDATE documents SET status = ?, rejection_reason = ?, status_set_by = ?, status_set_at = datetime('now'), updated_at = datetime('now') WHERE id = ?")
    .run(status, status === 'rejected' ? reason!.trim() : null, actor.label, doc.id);
  audit(ctx, { actorType: actor.type, actorId: actor.id, actorLabel: actor.label, action: 'document.status', entityType: 'document', entityId: doc.id, clientId: doc.client_id, details: { from: doc.status, to: status, reason: status === 'rejected' ? reason : undefined, title: doc.title }, ip: actor.ip });
}

export function updateDocumentMeta(ctx: AppContext, doc: DocumentRow, patch: { title?: string; tax_year?: number; category?: string }, actor: Actor) {
  const title = (patch.title ?? doc.title).trim() || doc.title;
  const year = patch.tax_year ?? doc.tax_year;
  const cat = patch.category ?? doc.category;
  if (!(DOCUMENT_CATEGORIES as readonly string[]).includes(cat)) throw new Error('Invalid category');
  if (!Number.isInteger(year) || year < 1990 || year > 2100) throw new Error('Invalid tax year');
  ctx.db.prepare("UPDATE documents SET title = ?, tax_year = ?, category = ?, updated_at = datetime('now') WHERE id = ?").run(title, year, cat, doc.id);
  audit(ctx, { actorType: actor.type, actorId: actor.id, actorLabel: actor.label, action: 'document.update', entityType: 'document', entityId: doc.id, clientId: doc.client_id, details: { from: { title: doc.title, tax_year: doc.tax_year, category: doc.category }, to: { title, tax_year: year, category: cat } }, ip: actor.ip });
}

/** Decrypting read stream for a stored version; logs the download. */
export function openVersionStream(ctx: AppContext, version: VersionRow, actor: Actor, clientId: string): NodeJS.ReadableStream {
  const decipher = ctx.cipher.fileDecryptor(Buffer.from(version.iv, 'base64'), Buffer.from(version.auth_tag, 'base64'));
  const src = fs.createReadStream(path.join(ctx.uploadsDir, version.stored_name));
  audit(ctx, { actorType: actor.type, actorId: actor.id, actorLabel: actor.label, action: 'document.download', entityType: 'document', entityId: version.document_id, clientId, details: { filename: version.original_filename, version: version.version_no }, ip: actor.ip, userAgent: actor.userAgent });
  return src.pipe(decipher);
}
