import 'dotenv/config';

export interface AppConfig {
  env: 'development' | 'production' | 'test';
  port: number;
  baseUrl: string;
  databaseUrl: string;
  /** Session-mode / direct connection used for migrations (DDL). Falls back to databaseUrl. */
  directDatabaseUrl: string;
  dbPoolMax: number;
  supabaseUrl: string;
  supabaseServiceRoleKey: string;
  storageBucket: string;
  encryptionKey: Buffer; // 32 bytes
  sessionSecret: Buffer;
  cookieSecure: boolean;
  trustProxy: boolean;
  cronSecret?: string;
  /** One-time first-admin bootstrap token; remove from the environment after setup. */
  bootstrapToken?: string;
  smtp?: { host: string; port: number; secure: boolean; user?: string; pass?: string; from: string };
}

/** Thrown when the environment is incomplete. `message` is safe to show: it names variables, never values. */
export class ConfigError extends Error {
  constructor(
    public readonly problems: string[],
  ) {
    super(
      'The application cannot start because its environment is incomplete:\n' +
        problems.map((p) => `  - ${p}`).join('\n') +
        '\nSet these in Vercel (Project → Settings → Environment Variables) or in .env, then redeploy. See .env.example for a description of each.',
    );
    this.name = 'ConfigError';
  }
}

export const REQUIRED_ENV = ['DATABASE_URL', 'SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'APP_ENCRYPTION_KEY', 'SESSION_SECRET'] as const;

export function loadConfig(overrides: Partial<AppConfig> = {}): AppConfig {
  const env = (process.env.NODE_ENV as AppConfig['env']) || 'development';
  const problems: string[] = [];
  const str = (name: string, provided?: string): string => {
    if (provided) return provided;
    const v = process.env[name];
    if (!v) problems.push(`${name} is not set.`);
    return v ?? '';
  };
  const key = (name: string, minBytes: number, exact: boolean, provided?: Buffer): Buffer => {
    if (provided) return provided;
    const raw = process.env[name];
    if (!raw) {
      problems.push(`${name} is not set. Generate it with "npm run gen-keys".`);
      return Buffer.alloc(0);
    }
    const buf = Buffer.from(raw, 'base64');
    if (exact ? buf.length !== minBytes : buf.length < minBytes) problems.push(`${name} must be base64 of ${exact ? 'exactly' : 'at least'} ${minBytes} random bytes (run "npm run gen-keys").`);
    return buf;
  };

  const databaseUrl = str('DATABASE_URL', overrides.databaseUrl);
  const supabaseUrl = str('SUPABASE_URL', overrides.supabaseUrl);
  if (supabaseUrl && !/^https?:\/\//.test(supabaseUrl)) problems.push('SUPABASE_URL must be a full URL such as https://xyz.supabase.co.');
  const supabaseServiceRoleKey = str('SUPABASE_SERVICE_ROLE_KEY', overrides.supabaseServiceRoleKey);
  const encryptionKey = key('APP_ENCRYPTION_KEY', 32, true, overrides.encryptionKey);
  const sessionSecret = key('SESSION_SECRET', 32, false, overrides.sessionSecret);
  if (databaseUrl && !/^postgres(ql)?:\/\//.test(databaseUrl)) problems.push('DATABASE_URL must be a postgres:// connection string.');

  const smtpHost = process.env.SMTP_HOST;
  const cookieSecure = overrides.cookieSecure ?? (process.env.COOKIE_SECURE ? process.env.COOKIE_SECURE === 'true' : !!process.env.VERCEL);
  if (env === 'production' && !cookieSecure) {
    // Refuse to run production with insecure cookies: session cookies would travel in clear text.
    problems.push('COOKIE_SECURE must be "true" when NODE_ENV=production (serve the app over HTTPS).');
  }
  if (problems.length) throw new ConfigError(problems);

  return {
    env,
    port: Number(process.env.PORT || 3000),
    baseUrl: (process.env.BASE_URL || (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : `http://localhost:${process.env.PORT || 3000}`)).replace(/\/$/, ''),
    databaseUrl,
    directDatabaseUrl: process.env.DIRECT_DATABASE_URL || databaseUrl,
    dbPoolMax: Number(process.env.DB_POOL_MAX || (process.env.VERCEL ? 2 : 5)),
    supabaseUrl,
    supabaseServiceRoleKey,
    storageBucket: process.env.SUPABASE_STORAGE_BUCKET || 'vault',
    encryptionKey,
    sessionSecret,
    cookieSecure,
    trustProxy: process.env.TRUST_PROXY ? process.env.TRUST_PROXY === 'true' : !!process.env.VERCEL,
    cronSecret: process.env.CRON_SECRET || undefined,
    bootstrapToken: process.env.BOOTSTRAP_TOKEN || undefined,
    smtp: smtpHost
      ? {
          host: smtpHost,
          port: Number(process.env.SMTP_PORT || 587),
          // SMTP_SECURE=true means implicit TLS (port 465); otherwise STARTTLS is negotiated when offered.
          secure: process.env.SMTP_SECURE ? process.env.SMTP_SECURE === 'true' : Number(process.env.SMTP_PORT || 587) === 465,
          user: process.env.SMTP_USER || undefined,
          pass: process.env.SMTP_PASS || undefined,
          from: process.env.SMTP_FROM || 'no-reply@localhost',
        }
      : undefined,
    ...overrides,
  };
}
