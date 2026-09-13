import 'dotenv/config';
import path from 'node:path';

export interface AppConfig {
  env: 'development' | 'production' | 'test';
  port: number;
  baseUrl: string;
  dataDir: string;
  dbPath: string; // ':memory:' allowed for tests
  encryptionKey: Buffer; // 32 bytes
  sessionSecret: Buffer;
  cookieSecure: boolean;
  trustProxy: boolean;
  smtp?: { host: string; port: number; user?: string; pass?: string; from: string };
}

function requiredKey(name: string, minBytes: number): Buffer {
  const raw = process.env[name];
  if (!raw) {
    throw new Error(
      `${name} is not set. Run "npm run gen-keys" and put the values in .env (see .env.example).`,
    );
  }
  const buf = Buffer.from(raw, 'base64');
  if (buf.length < minBytes) throw new Error(`${name} must decode to at least ${minBytes} bytes`);
  return buf;
}

export function loadConfig(overrides: Partial<AppConfig> = {}): AppConfig {
  const env = (process.env.NODE_ENV as AppConfig['env']) || 'development';
  const dataDir = path.resolve(process.env.DATA_DIR || './data');
  const smtpHost = process.env.SMTP_HOST;
  const cfg: AppConfig = {
    env,
    port: Number(process.env.PORT || 3000),
    baseUrl: (process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, ''),
    dataDir,
    dbPath: path.join(dataDir, 'taxonomy.sqlite'),
    encryptionKey: overrides.encryptionKey ?? requiredKey('APP_ENCRYPTION_KEY', 32),
    sessionSecret: overrides.sessionSecret ?? requiredKey('SESSION_SECRET', 32),
    cookieSecure: process.env.COOKIE_SECURE === 'true',
    trustProxy: process.env.TRUST_PROXY === 'true',
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
