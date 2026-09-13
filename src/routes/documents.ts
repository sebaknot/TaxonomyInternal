import { Router, type Request, type Response, type NextFunction } from 'express';
import { HttpError, requireRole, csrfAfterUpload } from '../middleware/index.js';
import { can, canAccessClient } from '../services/permissions.js';
import { getClient, type Actor } from '../services/clients.js';
import * as D from '../services/documents.js';
import { documentUploader } from '../lib/upload.js';
import { DOCUMENT_CATEGORIES } from '../lib/constants.js';
import fs from 'node:fs';

function actorOf(req: Request): Actor {
  return { type: 'user', id: req.user!.id, label: req.user!.email, ip: req.meta.ip, userAgent: req.meta.userAgent };
}

/** Loads document + client and enforces client access. */
function loadDocument(req: Request, res: Response, next: NextFunction) {
  const doc = D.getDocument(req.ctx, String(req.params.docId));
  const client = doc && getClient(req.ctx, doc.client_id);
  if (!doc || !client || !canAccessClient(req.user!, client)) return next(new HttpError(404, 'Document not found.'));
  res.locals.document = doc;
  res.locals.client = client;
  next();
}

export function documentsRouter() {
  const r = Router();
  let uploader: ReturnType<typeof documentUploader> | null = null;
  const single = (req: Request, res: Response, next: NextFunction) => {
    uploader ??= documentUploader(req.ctx);
    uploader.single('file')(req, res, (err) => (err ? next(new HttpError(400, err.message)) : next()));
  };

  r.post('/clients/:id/documents', requireRole(can.uploadDocuments), single, csrfAfterUpload, async (req, res, next) => {
    const client = getClient(req.ctx, String(req.params.id));
    const file = req.file;
    if (!client || !canAccessClient(req.user!, client)) {
      if (file) fs.rmSync(file.path, { force: true });
      return next(new HttpError(404, 'Client not found.'));
    }
    if (!file) {
      req.flash('error', 'Choose a file to upload.');
      return res.redirect(`/clients/${client.id}#vault`);
    }
    try {
      const { document } = await D.uploadDocument(
        req.ctx,
        {
          clientId: client.id,
          taxYear: parseInt(String(req.body.tax_year), 10),
          category: String(req.body.category || ''),
          tempPath: file.path,
          originalFilename: file.originalname,
          mimeType: file.mimetype,
          replaceDocumentId: req.body.replace_document_id ? String(req.body.replace_document_id) : null,
          title: req.body.title ? String(req.body.title) : null,
        },
        actorOf(req),
      );
      req.flash('success', `Uploaded ${file.originalname}.`);
      res.redirect(`/documents/${document.id}`);
    } catch (err) {
      fs.rmSync(file.path, { force: true });
      req.flash('error', (err as Error).message);
      res.redirect(`/clients/${client.id}#vault`);
    }
  });

  r.get('/documents/:docId', requireRole(can.downloadDocuments), loadDocument, (req, res) => {
    const doc = res.locals.document as D.DocumentRow;
    res.render('documents/show', { title: doc.title, document: doc, client: res.locals.client, versions: D.listVersions(req.ctx, doc.id), can, categories: DOCUMENT_CATEGORIES });
  });

  r.post('/documents/:docId/status', requireRole(can.setDocumentStatus), loadDocument, (req, res) => {
    try {
      D.setDocumentStatus(req.ctx, res.locals.document, String(req.body.status || ''), req.body.reason ? String(req.body.reason) : null, actorOf(req));
      req.flash('success', 'Status updated.');
    } catch (err) {
      req.flash('error', (err as Error).message);
    }
    res.redirect(`/documents/${res.locals.document.id}`);
  });

  r.post('/documents/:docId/meta', requireRole(can.setDocumentStatus), loadDocument, (req, res) => {
    try {
      D.updateDocumentMeta(req.ctx, res.locals.document, { title: String(req.body.title || ''), tax_year: parseInt(String(req.body.tax_year), 10), category: String(req.body.category || '') }, actorOf(req));
      req.flash('success', 'Document details updated.');
    } catch (err) {
      req.flash('error', (err as Error).message);
    }
    res.redirect(`/documents/${res.locals.document.id}`);
  });

  // Add a new version to an existing document.
  r.post('/documents/:docId/versions', requireRole(can.uploadDocuments), single, csrfAfterUpload, loadDocument, async (req, res, next) => {
    const doc = res.locals.document as D.DocumentRow;
    const file = req.file;
    if (!file) {
      req.flash('error', 'Choose a file to upload.');
      return res.redirect(`/documents/${doc.id}`);
    }
    try {
      await D.uploadDocument(req.ctx, { clientId: doc.client_id, taxYear: doc.tax_year, category: doc.category, tempPath: file.path, originalFilename: file.originalname, mimeType: file.mimetype, replaceDocumentId: doc.id }, actorOf(req));
      req.flash('success', 'New version uploaded. The previous version is kept.');
      res.redirect(`/documents/${doc.id}`);
    } catch (err) {
      fs.rmSync(file.path, { force: true });
      next(new HttpError(400, (err as Error).message));
    }
  });

  const download = (req: Request, res: Response, next: NextFunction) => {
    const doc = res.locals.document as D.DocumentRow;
    const version = req.params.versionId ? D.getVersion(req.ctx, String(req.params.versionId)) : D.listVersions(req.ctx, doc.id)[0];
    if (!version || version.document_id !== doc.id) return next(new HttpError(404, 'Version not found.'));
    res.setHeader('Content-Type', 'application/octet-stream'); // never sniff/inline user uploads
    res.setHeader('Content-Disposition', `attachment; filename="${D.safeFilename(version.original_filename)}"`);
    res.setHeader('Content-Length', String(version.size_bytes));
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const stream = D.openVersionStream(req.ctx, version, actorOf(req), doc.client_id);
    stream.on('error', (err) => next(err));
    stream.pipe(res);
  };
  r.get('/documents/:docId/download', requireRole(can.downloadDocuments), loadDocument, download);
  r.get('/documents/:docId/versions/:versionId/download', requireRole(can.downloadDocuments), loadDocument, download);

  return r;
}
