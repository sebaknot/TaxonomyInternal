import { Router } from 'express';
import type { AppContext } from '../context.js';
import { wrap } from '../middleware/index.js';

/**
 * Operational health check. Reports whether Postgres and Storage answer, migration state, and
 * whether first-admin bootstrap is still open. Never includes connection strings, keys, or raw
 * driver error text (which can embed hostnames or credentials).
 */
export function healthRouter(ctx: AppContext) {
  const r = Router();
  r.get(
    '/health',
    wrap(async (_req, res) => {
      const started = Date.now();
      const database = await (async () => {
        try {
          const t0 = Date.now();
          const migrations = await ctx.db.all<{ name: string }>('SELECT name FROM schema_migrations ORDER BY name');
          const usersExist = (await ctx.db.scalar<number>('SELECT COUNT(*) FROM users')) > 0;
          return { ok: true, latencyMs: Date.now() - t0, migrationsApplied: migrations.length, latestMigration: migrations.at(-1)?.name ?? null, usersExist };
        } catch (err) {
          const code = (err as any)?.code as string | undefined;
          const detail =
            code === '42P01' ? 'schema missing (run: npm run db:migrate)' : code === '28P01' ? 'authentication failed' : code === 'ECONNREFUSED' || code === 'ENOTFOUND' || code === 'ETIMEDOUT' ? `connection failed (${code})` : code ? `error ${code}` : 'unreachable';
          return { ok: false, detail, usersExist: null as boolean | null };
        }
      })();
      const storage = await ctx.storage.check();
      const ok = database.ok && storage.ok;
      res.status(ok ? 200 : 503).json({
        status: ok ? 'ok' : 'degraded',
        checkedAt: new Date().toISOString(),
        totalMs: Date.now() - started,
        checks: { database, storage },
        bootstrap: {
          tokenConfigured: !!ctx.config.bootstrapToken,
          setupOpen: !!ctx.config.bootstrapToken && database.usersExist === false,
          note: ctx.config.bootstrapToken && database.usersExist ? 'Setup is complete: remove BOOTSTRAP_TOKEN from the environment and redeploy.' : undefined,
        },
        config: { cookieSecure: ctx.config.cookieSecure, trustProxy: ctx.config.trustProxy, smtpConfigured: !!ctx.config.smtp, cronSecretConfigured: !!ctx.config.cronSecret, env: ctx.config.env },
      });
    }),
  );
  return r;
}
