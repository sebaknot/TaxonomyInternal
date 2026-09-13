import { Router, type Request, type Response, type NextFunction } from 'express';
import fs from 'node:fs';
import { HttpError, requireRole, csrfAfterUpload } from '../middleware/index.js';
import { can } from '../services/permissions.js';
import * as I from '../services/imports.js';
import { spreadsheetUploader } from '../lib/upload.js';

export function importsRouter() {
  const r = Router();
  r.use(requireRole(can.bulkImport));
  let uploader: ReturnType<typeof spreadsheetUploader> | null = null;
  const single = (req: Request, res: Response, next: NextFunction) => {
    uploader ??= spreadsheetUploader(req.ctx);
    uploader.single('file')(req, res, (err) => (err ? next(new HttpError(400, err.message)) : next()));
  };

  r.get('/', (req, res) => res.render('imports/index', { title: 'Bulk client import', imports: I.listImports(req.ctx) }));

  r.post('/', single, csrfAfterUpload, async (req, res, next) => {
    if (!req.file) {
      req.flash('error', 'Choose a CSV or Excel file.');
      return res.redirect('/imports');
    }
    try {
      const { record } = await I.stageImport(req.ctx, req.file.path, req.file.originalname, req.user!);
      res.redirect(`/imports/${record.id}`);
    } catch (err) {
      fs.rmSync(req.file.path, { force: true });
      req.flash('error', (err as Error).message);
      res.redirect('/imports');
    }
  });

  r.get('/:id', async (req, res, next) => {
    const record = I.getImport(req.ctx, String(req.params.id));
    if (!record) return next(new HttpError(404, 'Import not found'));
    if (record.status === 'completed') {
      return res.render('imports/summary', { title: 'Import results', record, summary: JSON.parse(record.summary || '{}'), mapping: JSON.parse(record.mapping || '{}') });
    }
    const headers: string[] = JSON.parse(record.headers);
    let preview: Record<string, string>[] = [];
    try {
      preview = (await I.loadStagedSheet(req.ctx, record)).rows.slice(0, 5);
    } catch (err) {
      req.flash('error', (err as Error).message);
    }
    res.render('imports/map', { title: 'Map columns', record, headers, preview, suggested: I.suggestMapping(headers), fields: I.IMPORT_FIELDS, error: null });
  });

  r.post('/:id/run', async (req, res, next) => {
    const record = I.getImport(req.ctx, String(req.params.id));
    if (!record) return next(new HttpError(404, 'Import not found'));
    if (record.status === 'completed') return res.redirect(`/imports/${record.id}`);
    const headers: string[] = JSON.parse(record.headers);
    const mapping: Record<string, string> = {};
    const validKeys = new Set(I.IMPORT_FIELDS.map((f) => f.key));
    for (const h of headers) {
      const v = String(req.body[`map[${h}]`] ?? 'skip');
      mapping[h] = validKeys.has(v as any) ? v : 'skip';
    }
    try {
      await I.runImport(req.ctx, record, mapping, req.user!, req.meta.ip);
      res.redirect(`/imports/${record.id}`);
    } catch (err) {
      const preview = (await I.loadStagedSheet(req.ctx, record)).rows.slice(0, 5);
      res.status(400).render('imports/map', { title: 'Map columns', record, headers, preview, suggested: mapping, fields: I.IMPORT_FIELDS, error: (err as Error).message });
    }
  });

  return r;
}
