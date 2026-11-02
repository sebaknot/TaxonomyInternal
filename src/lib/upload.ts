import multer from 'multer';
import path from 'node:path';
import { MAX_UPLOAD_BYTES } from './constants.js';

/**
 * Spreadsheet uploads for the import tool are small and are parsed in memory. (Document uploads
 * never pass through the server: see services/documents.ts for the direct-to-storage flow.)
 */
export function spreadsheetUploader() {
  return multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: Math.min(MAX_UPLOAD_BYTES, 4 * 1024 * 1024), files: 1 },
    fileFilter: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      if (!['.csv', '.tsv', '.txt', '.xlsx', '.xlsm', '.xls'].includes(ext)) return cb(new Error('Upload a .csv or .xlsx file.'));
      cb(null, true);
    },
  });
}
