import type { RequestHandler } from 'express';
import type { AppContext } from '../context.js';

/**
 * Fixed-window rate limiter backed by the rate_limits table, so limits hold across serverless
 * instances. One UPSERT per request; the window resets when it has elapsed.
 */
export function dbRateLimit(ctx: AppContext, opts: { name: string; windowMs: number; max: number }): RequestHandler {
  return async (req, res, next) => {
    try {
      const key = `${opts.name}:${req.meta?.ip || req.ip || 'unknown'}`;
      const row = await ctx.db.one<{ count: number }>(
        `INSERT INTO rate_limits (key, window_start, count) VALUES (?, now(), 1)
         ON CONFLICT (key) DO UPDATE SET
           count = CASE WHEN rate_limits.window_start < now() - make_interval(secs => ?) THEN 1 ELSE rate_limits.count + 1 END,
           window_start = CASE WHEN rate_limits.window_start < now() - make_interval(secs => ?) THEN now() ELSE rate_limits.window_start END
         RETURNING count`,
        key,
        opts.windowMs / 1000,
        opts.windowMs / 1000,
      );
      if ((row?.count ?? 0) > opts.max) {
        res.status(429);
        if (req.accepts(['html', 'json']) === 'json') return res.json({ error: 'Too many attempts. Try again later.' });
        return res.render('error', { title: 'Too many attempts', status: 429, message: 'Too many attempts. Please wait a few minutes and try again.' });
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

/** Removes stale limiter rows and expired sessions; called from the cron endpoint. */
export async function cleanupExpired(ctx: AppContext): Promise<{ rateLimits: number; sessions: number; portalSessions: number }> {
  const rateLimits = await ctx.db.run(`DELETE FROM rate_limits WHERE window_start < now() - interval '1 day'`);
  const sessions = await ctx.db.run(`DELETE FROM sessions WHERE expires_at < now() OR last_activity_at < now() - interval '1 day'`);
  const portalSessions = await ctx.db.run(`DELETE FROM portal_sessions WHERE expires_at < now() OR last_activity_at < now() - interval '1 day'`);
  return { rateLimits, sessions, portalSessions };
}
