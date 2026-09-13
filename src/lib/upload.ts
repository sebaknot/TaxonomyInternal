import multer from 'multer';
import path from 'node:path';
import fs from 'node:fs';
import { MAX_UPLOAD_BYTES, ALLOWED_UPLOAD_EXTENSIONS } from './constants.js';
import type { AppContext } from '../context.js';
import { randomToken } from './crypto.js';

/** Multer instance writing to a private temp dir; files are encrypted into the vault by the document service. */
export function documentUploader(ctx: AppContext) {
  const tmp = path.join(ctx.config.dataDir, 'tmp');
  fs.mkdirSync(tmp, { recursive: true, mode: 0o700 });
  return multer({
    storage: multer.diskStorage({ destination: tmp, filename: (_req, _file, cb) => cb(null, randomToken(16)) }),
    limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 },
    fileFilter: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      if (!ALLOWED_UPLOAD_EXTENSIONS.has(ext)) return cb(new Error(`File type "${ext || 'unknown'}" is not allowed.`));
      cb(null, true);
    },
  });
}

export function spreadsheetUploader(ctx: AppContext) {
  const tmp = path.join(ctx.config.dataDir, 'tmp');
  fs.mkdirSync(tmp, { recursive: true, mode: 0o700 });
  return multer({
    storage: multer.diskStorage({ destination: tmp, filename: (_req, _file, cb) => cb(null, randomToken(16)) }),
    limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 },
    fileFilter: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      if (!['.csv', '.tsv', '.txt', '.xlsx', '.xlsm', '.xls'].includes(ext)) return cb(new Error('Upload a .csv or .xlsx file.'));
      cb(null, true);
    },
  });
}
