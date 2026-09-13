import express from 'express';
import helmet from 'helmet';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { AppConfig } from './config.js';
import { openDatabase } from './lib/db.js';
import { FieldCipher } from './lib/crypto.js';
import { createMailer } from './services/mailer.js';
import type { AppContext } from './context.js';
import { baseMiddleware, csrfProtection, errorHandler, requireAuth } from './middleware/index.js';
import { ensureDefaultTags } from './services/clients.js';
import { authRouter } from './routes/auth.js';
import { clientsRouter } from './routes/clients.js';
import { documentsRouter } from './routes/documents.js';
import { adminRouter } from './routes/admin.js';
import { importsRouter } from './routes/imports.js';
import { portalRouter } from './routes/portal.js';
import { DOCUMENT_CATEGORIES, DOCUMENT_STATUSES, FILING_STATUSES, CLIENT_SOURCES, ROLES } from './lib/constants.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export function createContext(config: AppConfig): AppContext {
  fs.mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
  const uploadsDir = path.join(config.dataDir, 'uploads');
  const importsDir = path.join(config.dataDir, 'imports');
  fs.mkdirSync(uploadsDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(importsDir, { recursive: true, mode: 0o700 });
  const db = openDatabase(config.dbPath);
  const ctx: AppContext = { db, config, cipher: new FieldCipher(config.encryptionKey), mailer: createMailer(db, config), uploadsDir, importsDir };
  ensureDefaultTags(ctx);
  return ctx;
}

export function createApp(ctx: AppContext) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', ctx.config.trustProxy ? 1 : false);
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));
  app.locals.constants = { DOCUMENT_CATEGORIES, DOCUMENT_STATUSES, FILING_STATUSES, CLIENT_SOURCES, ROLES };

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:'],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          objectSrc: ["'none'"],
        },
      },
      referrerPolicy: { policy: 'no-referrer' },
      strictTransportSecurity: ctx.config.cookieSecure ? { maxAge: 31536000, includeSubDomains: true } : false,
    }),
  );
  app.use((_, res, next) => {
    // Never let browsers/proxies cache authenticated pages containing client data.
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.use('/static', express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));
  app.use(express.urlencoded({ extended: false, limit: '1mb' }));
  app.use(express.json({ limit: '256kb' }));
  app.use(baseMiddleware(ctx));
  app.use(csrfProtection);

  app.get('/healthz', (_req, res) => res.json({ ok: true }));
  app.use('/', authRouter());
  app.use('/portal', portalRouter());
  app.use(requireAuth);
  app.get('/', (req, res) => res.render('dashboard', { title: 'Dashboard' }));
  app.use('/clients', clientsRouter());
  app.use('/', documentsRouter());
  app.use('/imports', importsRouter());
  app.use('/admin', adminRouter());

  app.use((req, res) => res.status(404).render('error', { title: 'Not found', status: 404, message: 'Page not found.' }));
  app.use(errorHandler);
  return app;
}
