import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { HttpError, requireRole, wrap } from '../middleware/index.js';
import { can, canAccessClient } from '../services/permissions.js';
import { getClient, type Actor } from '../services/clients.js';
import * as D from '../services/documents.js';
import { DOCUMENT_CATEGORIES } from '../lib/constants.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function actorOf(req: Request): Actor {
  return { type: 'user', id: req.user!.id, label: req.user!.email, ip: req.meta.ip, userAgent: req.meta.userAgent };
}

/** Loads document + client and enforces client access. */
const loadDocument = wrap(async (req: Request, res: Response, next: NextFunction) => {
  const id = String(req.params.docId);
  const doc = UUID.test(id) ? await D.getDocument(req.ctx, id) : undefined;
  const client = doc && (await getClient(req.ctx, doc.client_id));
  if (!doc || !client || !canAccessClient(req.user!, client)) return next(new HttpError(404, 'Document not found.'));
  res.locals.document = doc;
  res.locals.client = client;
  next();
});

export const initSchema = z.object({
  filename: z.string().min(1).max(255),
  size: z.number().int().positive(),
  mime: z.string().max(100).optional().nullable(),
  tax_year: z.coerce.number().int(),
  category: z.string().min(1),
  title: z.string().max(200).optional().nullable(),
  replace_document_id: z.string().uuid().optional().nullable(),
});
export const completeSchema = z.object({ sha256: z.string().length(64), size: z.number().int().positive() });

export function documentsRouter() {
  const r = Router();

  // Step 1 of a direct-to-storage upload: returns signed URL + data key.
  r.post(
    '/clients/:id/documents/init',
    requireRole(can.uploadDocuments),
    wrap(async (req, res) => {
      const id = String(req.params.id);
      const client = UUID.test(id) ? await getClient(req.ctx, id) : undefined;
      if (!client || !canAccessClient(req.user!, client)) throw new HttpError(404, 'Client not found.');
      const p = initSchema.safeParse(req.body);
      if (!p.success) throw new HttpError(400, 'Invalid upload request');
      try {
        const result = await D.initUpload(
          req.ctx,
          { clientId: client.id, taxYear: p.data.tax_year, category: p.data.category, originalFilename: p.data.filename, mimeType: p.data.mime ?? null, sizeBytes: p.data.size, replaceDocumentId: p.data.replace_document_id ?? null, title: p.data.title ?? null },
          actorOf(req),
        );
        res.json(result);
      } catch (err) {
        throw new HttpError(400, (err as Error).message);
      }
    }),
  );

  // Step 2: the browser has PUT the ciphertext; finalise.
  r.post(
    '/documents/uploads/:versionId/complete',
    requireRole(can.uploadDocuments),
    wrap(async (req, res) => {
      const p = completeSchema.safeParse(req.body);
      const vid = String(req.params.versionId);
      if (!p.success || !UUID.test(vid)) throw new HttpError(400, 'Invalid completion request');
      const v = await D.getVersion(req.ctx, vid);
      const client = v && (await getClient(req.ctx, v.client_id));
      if (!v || !client || !canAccessClient(req.user!, client)) throw new HttpError(404, 'Upload not found.');
      try {
        const { document } = await D.completeUpload(req.ctx, vid, { sha256: p.data.sha256, sizeBytes: p.data.size }, actorOf(req));
        req.flash('success', `Uploaded ${v.original_filename}.`);
        res.json({ ok: true, documentId: document.id, redirect: `/documents/${document.id}` });
      } catch (err) {
        throw new HttpError(400, (err as Error).message);
      }
    }),
  );

  r.get(
    '/documents/:docId',
    requireRole(can.downloadDocuments),
    loadDocument,
    wrap(async (req, res) => {
      const doc = res.locals.document as D.DocumentRow;
      res.render('documents/show', { title: doc.title, document: doc, client: res.locals.client, versions: await D.listVersions(req.ctx, doc.id), can, categories: DOCUMENT_CATEGORIES });
    }),
  );

  r.post(
    '/documents/:docId/status',
    requireRole(can.setDocumentStatus),
    loadDocument,
    wrap(async (req, res) => {
      try {
        await D.setDocumentStatus(req.ctx, res.locals.document, String(req.body.status || ''), req.body.reason ? String(req.body.reason) : null, actorOf(req));
        req.flash('success', 'Status updated.');
      } catch (err) {
        req.flash('error', (err as Error).message);
      }
      res.redirect(`/documents/${res.locals.document.id}`);
    }),
  );

  r.post(
    '/documents/:docId/meta',
    requireRole(can.setDocumentStatus),
    loadDocument,
    wrap(async (req, res) => {
      try {
        await D.updateDocumentMeta(req.ctx, res.locals.document, { title: String(req.body.title || ''), tax_year: parseInt(String(req.body.tax_year), 10), category: String(req.body.category || '') }, actorOf(req));
        req.flash('success', 'Document details updated.');
      } catch (err) {
        req.flash('error', (err as Error).message);
      }
      res.redirect(`/documents/${res.locals.document.id}`);
    }),
  );

  /** Download grant: signed ciphertext URL + key for the browser to decrypt. Audited as a download. */
  const grant = wrap(async (req: Request, res: Response) => {
    const doc = res.locals.document as D.DocumentRow;
    const vid = req.params.versionId ? String(req.params.versionId) : null;
    const version = vid ? (UUID.test(vid) ? await D.getVersion(req.ctx, vid) : undefined) : (await D.listVersions(req.ctx, doc.id))[0];
    if (!version || version.document_id !== doc.id || version.upload_state !== 'complete') throw new HttpError(404, 'Version not found.');
    res.json(await D.grantDownload(req.ctx, version, actorOf(req), doc.client_id));
  });
  r.post('/documents/:docId/download', requireRole(can.downloadDocuments), loadDocument, grant);
  r.post('/documents/:docId/versions/:versionId/download', requireRole(can.downloadDocuments), loadDocument, grant);

  return r;
}
