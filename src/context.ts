import type { DB } from './lib/db.js';
import type { AppConfig } from './config.js';
import { FieldCipher } from './lib/crypto.js';
import type { Mailer } from './services/mailer.js';

/** Everything services need, passed explicitly (no globals) so tests can spin up isolated apps. */
export interface AppContext {
  db: DB;
  config: AppConfig;
  cipher: FieldCipher;
  mailer: Mailer;
  uploadsDir: string;
  importsDir: string;
}
