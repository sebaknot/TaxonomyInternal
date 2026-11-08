import express from 'express';
import helmet from 'helmet';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AppConfig } from './config.js';
import { DB } from './lib/db.js';
import { FieldCipher } from './lib/crypto.js';
import { createMailer } from './services/mailer.js';
import type { AppContext } from './context.js';
import { SupabaseStorage, type Storage } from './lib/storage.js';
import { baseMiddleware, csrfProtection, errorHandler, requireAuth, wrap } from './middleware/index.js';
import { cleanupExpired } from './middleware/rateLimit.js';
import { cleanupPendingUploads } from './services/documents.js';
import { authRouter } from './routes/auth.js';
import { clientsRouter } from './routes/clients.js';
import { documentsRouter } from './routes/documents.js';
import { adminRouter } from './routes/admin.js';
import { importsRouter } from './routes/imports.js';
import { portalRouter } from './routes/portal.js';
import { healthRouter } from './routes/health.js';
import { setupRouter } from './routes/setup.js';
import { DOCUMENT_CATEGORIES, DOCUMENT_STATUSES, FILING_STATUSES, CLIENT_SOURCES, ROLES } from './lib/constants.js';
import { safeEqual } from './lib/crypto.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Builds the application context. Cheap and synchronous: the pool connects lazily, so it is safe at cold start. */
export function createContext(config: AppConfig, overrides: { db?: DB; storage?: Storage } = {}): AppContext {
  const db = overrides.db ?? DB.fromUrl(config.databaseUrl, { max: config.dbPoolMax });
  const storage = overrides.storage ?? new SupabaseStorage({ url: config.supabaseUrl, serviceRoleKey: config.supabaseServiceRoleKey, bucket: config.storageBucket });
  return { db, config, cipher: new FieldCipher(config.encryptionKey), mailer: createMailer(db, config), storage };
}

export function createApp(ctx: AppContext) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', ctx.config.trustProxy ? 1 : false);
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));
  app.set('view cache', ctx.config.env === 'production');
  app.locals.constants = { DOCUMENT_CATEGORIES, DOCUMENT_STATUSES, FILING_STATUSES, CLIENT_SOURCES, ROLES };

  const supabaseOrigin = safeOrigin(ctx.config.supabaseUrl);
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:'],
          // The browser talks to Supabase Storage directly for encrypted uploads/downloads.
          connectSrc: ["'self'", ...(supabaseOrigin ? [supabaseOrigin] : [])],
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
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  // Locally express serves /static; on Vercel the same files are served from the CDN via /public.
  app.use('/static', express.static(path.join(__dirname, '..', '..', 'public', 'static'), { maxAge: '1h' }));
  app.use(express.urlencoded({ extended: false, limit: '1mb' }));
  app.use(express.json({ limit: '256kb' }));

  app.get('/healthz', (_req, res) => res.json({ ok: true }));
  app.use(healthRouter(ctx));
  // Scheduled maintenance (Vercel Cron sends Authorization: Bearer <CRON_SECRET>).
  app.get(
    '/api/cron/cleanup',
    wrap(async (req, res) => {
      const auth = String(req.headers.authorization || '');
      if (!ctx.config.cronSecret || !safeEqual(auth, `Bearer ${ctx.config.cronSecret}`)) return res.status(401).json({ error: 'unauthorized' });
      const expired = await cleanupExpired(ctx);
      const pendingUploads = await cleanupPendingUploads(ctx);
      res.json({ ok: true, ...expired, pendingUploads });
    }),
  );

  app.use(baseMiddleware(ctx));
  app.use(csrfProtection);

  app.use('/', setupRouter(ctx));
  app.use('/', authRouter(ctx));
  app.use('/portal', portalRouter(ctx));
  app.use(requireAuth);
  app.get('/', (_req, res) => res.render('dashboard', { title: 'Dashboard' }));
  app.use('/clients', clientsRouter());
  app.use('/', documentsRouter());
  app.use('/imports', importsRouter());
  app.use('/admin', adminRouter());

  app.use((_req, res) => res.status(404).render('error', { title: 'Not found', status: 404, message: 'Page not found.' }));
  app.use(errorHandler);
  return app;
}

function safeOrigin(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}
