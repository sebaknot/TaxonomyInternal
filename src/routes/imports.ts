import { Router, type Request, type Response, type NextFunction } from 'express';
import { HttpError, requireRole, csrfAfterUpload, wrap } from '../middleware/index.js';
import { can } from '../services/permissions.js';
import * as I from '../services/imports.js';
import { spreadsheetUploader } from '../lib/upload.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function importsRouter() {
  const r = Router();
  r.use(requireRole(can.bulkImport));
  const uploader = spreadsheetUploader();
  const single = (req: Request, res: Response, next: NextFunction) => {
    uploader.single('file')(req, res, (err) => (err ? next(new HttpError(400, err.message)) : next()));
  };
  const load = wrap(async (req: Request, res: Response, next: NextFunction) => {
    const id = String(req.params.id);
    const record = UUID.test(id) ? await I.getImport(req.ctx, id) : undefined;
    if (!record) return next(new HttpError(404, 'Import not found'));
    res.locals.record = record;
    next();
  });

  r.get(
    '/',
    wrap(async (req, res) => res.render('imports/index', { title: 'Bulk client import', imports: await I.listImports(req.ctx) })),
  );

  r.post(
    '/',
    single,
    csrfAfterUpload,
    wrap(async (req, res) => {
      if (!req.file) {
        req.flash('error', 'Choose a CSV or Excel file.');
        return res.redirect('/imports');
      }
      try {
        const { record } = await I.stageImport(req.ctx, req.file.buffer, req.file.originalname, req.user!);
        res.redirect(`/imports/${record.id}`);
      } catch (err) {
        req.flash('error', (err as Error).message);
        res.redirect('/imports');
      }
    }),
  );

  r.get(
    '/:id',
    load,
    wrap(async (req, res) => {
      const record = res.locals.record as I.ImportRow;
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
    }),
  );

  r.post(
    '/:id/run',
    load,
    wrap(async (req, res) => {
      const record = res.locals.record as I.ImportRow;
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
    }),
  );

  return r;
}
