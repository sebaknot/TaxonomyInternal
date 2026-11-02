import 'dotenv/config';

export interface AppConfig {
  env: 'development' | 'production' | 'test';
  port: number;
  baseUrl: string;
  databaseUrl: string;
  dbPoolMax: number;
  supabaseUrl: string;
  supabaseServiceRoleKey: string;
  storageBucket: string;
  encryptionKey: Buffer; // 32 bytes
  sessionSecret: Buffer;
  cookieSecure: boolean;
  trustProxy: boolean;
  cronSecret?: string;
  smtp?: { host: string; port: number; user?: string; pass?: string; from: string };
}

function requiredKey(name: string, minBytes: number): Buffer {
  const raw = process.env[name];
  if (!raw) throw new Error(`${name} is not set. Run "npm run gen-keys" and add the values to your environment (see .env.example).`);
  const buf = Buffer.from(raw, 'base64');
  if (buf.length < minBytes) throw new Error(`${name} must decode to at least ${minBytes} bytes`);
  return buf;
}
function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set (see .env.example).`);
  return v;
}

export function loadConfig(overrides: Partial<AppConfig> = {}): AppConfig {
  const env = (process.env.NODE_ENV as AppConfig['env']) || 'development';
  const smtpHost = process.env.SMTP_HOST;
  const cfg: AppConfig = {
    env,
    port: Number(process.env.PORT || 3000),
    baseUrl: (process.env.BASE_URL || (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : `http://localhost:${process.env.PORT || 3000}`)).replace(/\/$/, ''),
    databaseUrl: overrides.databaseUrl ?? required('DATABASE_URL'),
    dbPoolMax: Number(process.env.DB_POOL_MAX || (process.env.VERCEL ? 2 : 5)),
    supabaseUrl: overrides.supabaseUrl ?? required('SUPABASE_URL'),
    supabaseServiceRoleKey: overrides.supabaseServiceRoleKey ?? required('SUPABASE_SERVICE_ROLE_KEY'),
    storageBucket: process.env.SUPABASE_STORAGE_BUCKET || 'vault',
    encryptionKey: overrides.encryptionKey ?? requiredKey('APP_ENCRYPTION_KEY', 32),
    sessionSecret: overrides.sessionSecret ?? requiredKey('SESSION_SECRET', 32),
    // Vercel always terminates TLS, so Secure cookies default on there.
    cookieSecure: process.env.COOKIE_SECURE ? process.env.COOKIE_SECURE === 'true' : !!process.env.VERCEL,
    trustProxy: process.env.TRUST_PROXY ? process.env.TRUST_PROXY === 'true' : !!process.env.VERCEL,
    cronSecret: process.env.CRON_SECRET || undefined,
    smtp: smtpHost
      ? {
          host: smtpHost,
          port: Number(process.env.SMTP_PORT || 587),
          user: process.env.SMTP_USER || undefined,
          pass: process.env.SMTP_PASS || undefined,
          from: process.env.SMTP_FROM || 'no-reply@localhost',
        }
      : undefined,
    ...overrides,
  };
  if (cfg.encryptionKey.length !== 32) throw new Error('APP_ENCRYPTION_KEY must be exactly 32 bytes');
  if (cfg.env === 'production' && !cfg.cookieSecure) {
    // Refuse to run production with insecure cookies: session cookies would travel in clear text.
    throw new Error('COOKIE_SECURE must be "true" in production (serve the app over HTTPS).');
  }
  return cfg;
}
