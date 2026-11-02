import path from 'node:path';
import crypto from 'node:crypto';
import type { AppContext } from '../context.js';
import { newId, randomToken } from '../lib/crypto.js';
import { audit } from './audit.js';
import type { Actor } from './clients.js';
import { DOCUMENT_CATEGORIES, DOCUMENT_STATUSES, ALLOWED_UPLOAD_EXTENSIONS, MAX_UPLOAD_BYTES, type DocumentStatus } from '../lib/constants.js';

/**
 * Document vault on Supabase Storage with envelope encryption.
 *
 *  1. init:     the server creates a pending version row, a random 256-bit data key + 96-bit IV,
 *               stores the key wrapped with the master key (data_key_enc), and hands the browser
 *               a signed upload URL plus the raw data key/IV over the authenticated session.
 *  2. upload:   the browser encrypts the file with WebCrypto AES-256-GCM and PUTs the ciphertext
 *               (ct || 16-byte tag) straight to Storage. Vercel never sees the bytes.
 *  3. complete: the browser reports plaintext size + SHA-256; the server verifies the object exists
 *               with the expected ciphertext size and finalises the document/version.
 *  4. download: the server unwraps the key, logs the download, and returns a signed download URL
 *               with key + IV; the browser fetches the ciphertext and decrypts locally.
 *
 * Supabase therefore only ever stores ciphertext and never has the key.
 */

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
  document_id: string | null;
  client_id: string;
  version_no: number | null;
  original_filename: string;
  storage_path: string;
  size_bytes: number | null;
  mime_type: string | null;
  sha256: string | null;
  data_key_enc: string;
  upload_state: 'pending' | 'complete';
  pending_meta: string | null;
  uploaded_by_type: string;
  uploaded_by_id: string | null;
  uploaded_by_label: string;
  created_at: string;
  uploaded_at: string | null;
}

export const GCM_TAG_BYTES = 16;
const UPLOAD_PENDING_MAX_AGE_HOURS = 24;

export function validateUploadName(originalName: string): string | null {
  const ext = path.extname(originalName).toLowerCase();
  if (!ALLOWED_UPLOAD_EXTENSIONS.has(ext)) return `File type "${ext || 'unknown'}" is not allowed.`;
  return null;
}
export function safeFilename(name: string): string {
  return path.basename(name).replace(/[\r\n"\\]/g, '_').slice(0, 200) || 'file';
}

function wrapKey(ctx: AppContext, versionId: string, key: Buffer, iv: Buffer): string {
  return ctx.cipher.encrypt(`${key.toString('base64')}:${iv.toString('base64')}`, `filekey:${versionId}`);
}
export function unwrapKey(ctx: AppContext, version: VersionRow): { key: Buffer; iv: Buffer } {
  const [k, i] = ctx.cipher.decrypt(version.data_key_enc, `filekey:${version.id}`).split(':');
  return { key: Buffer.from(k, 'base64'), iv: Buffer.from(i, 'base64') };
}

export interface InitUploadInput {
  clientId: string;
  taxYear: number;
  category: string;
  originalFilename: string;
  mimeType?: string | null;
  sizeBytes: number;
  /** When set, the upload becomes a new version of this existing document. */
  replaceDocumentId?: string | null;
  title?: string | null;
}
export interface InitUploadResult {
  versionId: string;
  uploadUrl: string;
  key: string; // base64 raw AES-256 key
  iv: string; // base64 96-bit IV
  expectedCiphertextBytes: number;
}

export async function initUpload(ctx: AppContext, input: InitUploadInput, actor: Actor): Promise<InitUploadResult> {
  if (!(DOCUMENT_CATEGORIES as readonly string[]).includes(input.category)) throw new Error('Invalid category');
  if (!Number.isInteger(input.taxYear) || input.taxYear < 1990 || input.taxYear > 2100) throw new Error('Invalid tax year');
  if (!Number.isInteger(input.sizeBytes) || input.sizeBytes <= 0) throw new Error('File is empty');
  if (input.sizeBytes > MAX_UPLOAD_BYTES) throw new Error(`File too large (max ${Math.round(MAX_UPLOAD_BYTES / 1024 / 1024)} MB)`);
  const nameErr = validateUploadName(input.originalFilename);
  if (nameErr) throw new Error(nameErr);
  if (input.replaceDocumentId) {
    const existing = await getDocument(ctx, input.replaceDocumentId);
    if (!existing || existing.client_id !== input.clientId) throw new Error('Document to replace not found');
  }
  const versionId = newId();
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const storagePath = `clients/${input.clientId}/${versionId}-${randomToken(8)}.bin`;
  await ctx.db.run(
    `INSERT INTO document_versions (id, document_id, client_id, original_filename, storage_path, size_bytes, mime_type, data_key_enc, upload_state, pending_meta, uploaded_by_type, uploaded_by_id, uploaded_by_label)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)`,
    versionId,
    input.replaceDocumentId ?? null,
    input.clientId,
    safeFilename(input.originalFilename),
    storagePath,
    input.sizeBytes,
    input.mimeType ?? null,
    wrapKey(ctx, versionId, key, iv),
    JSON.stringify({ tax_year: input.taxYear, category: input.category, title: (input.title || '').trim() || null }),
    actor.type === 'client' ? 'client' : 'user',
    actor.id ?? null,
    actor.label,
  );
  const uploadUrl = await ctx.storage.createSignedUploadUrl(storagePath);
  return { versionId, uploadUrl, key: key.toString('base64'), iv: iv.toString('base64'), expectedCiphertextBytes: input.sizeBytes + GCM_TAG_BYTES };
}

/** Finalises an upload after the browser has PUT the ciphertext. Verifies the object is really there. */
export async function completeUpload(ctx: AppContext, versionId: string, report: { sha256: string; sizeBytes: number }, actor: Actor): Promise<{ document: DocumentRow; version: VersionRow }> {
  const v = await getVersion(ctx, versionId);
  if (!v || v.upload_state !== 'pending') throw new Error('Upload not found or already completed');
  if (actor.type === 'client' ? v.uploaded_by_type !== 'client' : v.uploaded_by_type !== 'user' || (v.uploaded_by_id ?? null) !== (actor.id ?? null)) throw new Error('Upload belongs to someone else');
  if (!/^[0-9a-f]{64}$/.test(report.sha256)) throw new Error('Invalid checksum');
  if (report.sizeBytes !== Number(v.size_bytes)) throw new Error('Size mismatch');
  const stored = await ctx.storage.objectSize(v.storage_path);
  if (stored == null) throw new Error('The encrypted file did not reach storage. Please try again.');
  if (stored !== report.sizeBytes + GCM_TAG_BYTES) throw new Error(`Stored object has unexpected size (${stored} bytes)`);

  const meta = JSON.parse(v.pending_meta || '{}') as { tax_year: number; category: string; title: string | null };
  let docId = v.document_id;
  let versionNo = 1;
  await ctx.db.tx(async (t) => {
    if (docId) {
      versionNo = ((await t.scalar<number | null>('SELECT MAX(version_no) FROM document_versions WHERE document_id = ? AND upload_state = ?', docId, 'complete')) ?? 0) + 1;
      await t.run('UPDATE documents SET updated_at = now() WHERE id = ?', docId);
    } else {
      docId = newId();
      await t.run('INSERT INTO documents (id, client_id, tax_year, category, title) VALUES (?, ?, ?, ?, ?)', docId, v.client_id, meta.tax_year, meta.category, meta.title || v.original_filename);
    }
    await t.run(
      `UPDATE document_versions SET document_id = ?, version_no = ?, sha256 = ?, upload_state = 'complete', pending_meta = NULL, uploaded_at = now() WHERE id = ?`,
      docId,
      versionNo,
      report.sha256,
      versionId,
    );
  });
  await audit(ctx, {
    actorType: actor.type,
    actorId: actor.id,
    actorLabel: actor.label,
    action: versionNo > 1 ? 'document.new_version' : 'document.upload',
    entityType: 'document',
    entityId: docId!,
    clientId: v.client_id,
    details: { filename: v.original_filename, tax_year: meta.tax_year, category: meta.category, version: versionNo, size: report.sizeBytes },
    ip: actor.ip,
    userAgent: actor.userAgent,
  });
  return { document: (await getDocument(ctx, docId!))!, version: (await getVersion(ctx, versionId))! };
}

/** Server-side upload helper (tests, scripts): encrypts in Node and writes straight to storage. */
export async function uploadFromServer(ctx: AppContext, input: Omit<InitUploadInput, 'sizeBytes'> & { content: Buffer }, actor: Actor) {
  const init = await initUpload(ctx, { ...input, sizeBytes: input.content.length }, actor);
  const { ciphertext, sha256 } = encryptForUpload(input.content, Buffer.from(init.key, 'base64'), Buffer.from(init.iv, 'base64'));
  const v = (await getVersion(ctx, init.versionId))!;
  await ctx.storage.put(v.storage_path, ciphertext);
  return completeUpload(ctx, init.versionId, { sha256, sizeBytes: input.content.length }, actor);
}

/** Same construction WebCrypto produces: ciphertext || tag. */
export function encryptForUpload(plaintext: Buffer, key: Buffer, iv: Buffer): { ciphertext: Buffer; sha256: string } {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return { ciphertext: ct, sha256: crypto.createHash('sha256').update(plaintext).digest('hex') };
}
export function decryptDownloaded(ciphertext: Buffer, key: Buffer, iv: Buffer): Buffer {
  const tag = ciphertext.subarray(ciphertext.length - GCM_TAG_BYTES);
  const body = ciphertext.subarray(0, ciphertext.length - GCM_TAG_BYTES);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

export function getDocument(ctx: AppContext, id: string) {
  return ctx.db.one<DocumentRow>('SELECT * FROM documents WHERE id = ?', id);
}
export function getVersion(ctx: AppContext, id: string) {
  return ctx.db.one<VersionRow>('SELECT * FROM document_versions WHERE id = ?', id);
}
export function listVersions(ctx: AppContext, documentId: string) {
  return ctx.db.all<VersionRow>(`SELECT * FROM document_versions WHERE document_id = ? AND upload_state = 'complete' ORDER BY version_no DESC`, documentId);
}

export interface VaultDoc extends DocumentRow {
  versions: VersionRow[];
  latest: VersionRow;
}
/** Documents organized by tax year (desc) then category (spec order). */
export async function clientVault(ctx: AppContext, clientId: string): Promise<{ year: number; categories: { category: string; documents: VaultDoc[] }[] }[]> {
  const docs = await ctx.db.all<DocumentRow>('SELECT * FROM documents WHERE client_id = ? ORDER BY tax_year DESC, created_at', clientId);
  const versions = await ctx.db.all<VersionRow>(
    `SELECT v.* FROM document_versions v JOIN documents d ON d.id = v.document_id WHERE d.client_id = ? AND v.upload_state = 'complete' ORDER BY v.version_no DESC`,
    clientId,
  );
  const byDoc = new Map<string, VersionRow[]>();
  for (const v of versions) {
    if (!byDoc.has(v.document_id!)) byDoc.set(v.document_id!, []);
    byDoc.get(v.document_id!)!.push(v);
  }
  const byYear = new Map<number, Map<string, VaultDoc[]>>();
  for (const d of docs) {
    const vs = byDoc.get(d.id) ?? [];
    if (!vs.length) continue;
    if (!byYear.has(d.tax_year)) byYear.set(d.tax_year, new Map());
    const cats = byYear.get(d.tax_year)!;
    if (!cats.has(d.category)) cats.set(d.category, []);
    cats.get(d.category)!.push({ ...d, versions: vs, latest: vs[0] });
  }
  return [...byYear.entries()]
    .sort((a, b) => b[0] - a[0])
    .map(([year, cats]) => ({
      year,
      categories: DOCUMENT_CATEGORIES.filter((c) => cats.has(c)).map((c) => ({ category: c, documents: cats.get(c)! })),
    }));
}

export async function setDocumentStatus(ctx: AppContext, doc: DocumentRow, status: string, reason: string | null, actor: Actor) {
  if (!(DOCUMENT_STATUSES as readonly string[]).includes(status)) throw new Error('Invalid status');
  if (status === 'rejected' && !(reason || '').trim()) throw new Error('A reason is required when rejecting a document');
  await ctx.db.run(
    'UPDATE documents SET status = ?, rejection_reason = ?, status_set_by = ?, status_set_at = now(), updated_at = now() WHERE id = ?',
    status,
    status === 'rejected' ? reason!.trim() : null,
    actor.label,
    doc.id,
  );
  await audit(ctx, { actorType: actor.type, actorId: actor.id, actorLabel: actor.label, action: 'document.status', entityType: 'document', entityId: doc.id, clientId: doc.client_id, details: { from: doc.status, to: status, reason: status === 'rejected' ? reason : undefined, title: doc.title }, ip: actor.ip });
}

export async function updateDocumentMeta(ctx: AppContext, doc: DocumentRow, patch: { title?: string; tax_year?: number; category?: string }, actor: Actor) {
  const title = (patch.title ?? doc.title).trim() || doc.title;
  const year = patch.tax_year ?? doc.tax_year;
  const cat = patch.category ?? doc.category;
  if (!(DOCUMENT_CATEGORIES as readonly string[]).includes(cat)) throw new Error('Invalid category');
  if (!Number.isInteger(year) || year < 1990 || year > 2100) throw new Error('Invalid tax year');
  await ctx.db.run('UPDATE documents SET title = ?, tax_year = ?, category = ?, updated_at = now() WHERE id = ?', title, year, cat, doc.id);
  await audit(ctx, { actorType: actor.type, actorId: actor.id, actorLabel: actor.label, action: 'document.update', entityType: 'document', entityId: doc.id, clientId: doc.client_id, details: { from: { title: doc.title, tax_year: doc.tax_year, category: doc.category }, to: { title, tax_year: year, category: cat } }, ip: actor.ip });
}

export interface DownloadGrant {
  url: string;
  key: string;
  iv: string;
  filename: string;
  sizeBytes: number;
  mimeType: string | null;
}
/** Issues a short-lived signed URL for the ciphertext plus the unwrapped key; the browser decrypts. Audited. */
export async function grantDownload(ctx: AppContext, version: VersionRow, actor: Actor, clientId: string): Promise<DownloadGrant> {
  if (version.upload_state !== 'complete') throw new Error('Version not available');
  const { key, iv } = unwrapKey(ctx, version);
  const url = await ctx.storage.createSignedDownloadUrl(version.storage_path, 120);
  await audit(ctx, { actorType: actor.type, actorId: actor.id, actorLabel: actor.label, action: 'document.download', entityType: 'document', entityId: version.document_id!, clientId, details: { filename: version.original_filename, version: version.version_no }, ip: actor.ip, userAgent: actor.userAgent });
  return { url, key: key.toString('base64'), iv: iv.toString('base64'), filename: version.original_filename, sizeBytes: Number(version.size_bytes), mimeType: version.mime_type };
}

/** Removes abandoned pending uploads (rows and any stray objects). */
export async function cleanupPendingUploads(ctx: AppContext): Promise<number> {
  const stale = await ctx.db.all<{ id: string; storage_path: string }>(
    `SELECT id, storage_path FROM document_versions WHERE upload_state = 'pending' AND created_at < now() - make_interval(hours => ?)`,
    UPLOAD_PENDING_MAX_AGE_HOURS,
  );
  if (!stale.length) return 0;
  try {
    await ctx.storage.remove(stale.map((s) => s.storage_path));
  } catch (err) {
    console.error('pending upload cleanup: storage remove failed', err);
  }
  await ctx.db.run('DELETE FROM document_versions WHERE id = ANY(?)', stale.map((s) => s.id));
  return stale.length;
}
