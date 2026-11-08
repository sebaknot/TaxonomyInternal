import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import type { AppContext } from '../context.js';
import { STAFF_COOKIE, cookieOptions, wrap, HttpError } from '../middleware/index.js';
import { dbRateLimit } from '../middleware/rateLimit.js';
import { createUser, validatePasswordStrength } from '../services/auth.js';
import { audit } from '../services/audit.js';
import { hmac, randomToken, safeEqual, sha256 } from '../lib/crypto.js';

/**
 * One-time first-admin bootstrap for a fresh deployment.
 *
 * Reachable only while BOTH hold: BOOTSTRAP_TOKEN is set in the environment, and the users table
 * is completely empty. Otherwise every /setup route is a plain 404 (indistinguishable from a
 * missing page). The token is submitted in a form body (never a query string, so it does not land
 * in request logs) and compared in constant time. Success issues a short-lived signed cookie that
 * unlocks the admin-creation form; creating the admin starts a password-only session and sends
 * the user straight into the mandatory TOTP enrollment, which shows the QR code, manual key and
 * one-time backup codes.
 */
const SETUP_COOKIE = 'tx_setup';
const SETUP_TTL_MS = 15 * 60_000;

export function setupRouter(ctx: AppContext) {
  const r = Router();
  const limiter = dbRateLimit(ctx, { name: 'setup', windowMs: 15 * 60_000, max: 10 });

  const usersExist = async () => (await ctx.db.scalar<number>('SELECT COUNT(*) FROM users')) > 0;

  /** 404 unless bootstrap is open. */
  const gate = wrap(async (_req: Request, _res: Response, next: NextFunction) => {
    if (!ctx.config.bootstrapToken || (await usersExist())) return next(new HttpError(404, 'Page not found.'));
    next();
  });

  const mintUnlock = () => {
    const exp = String(Date.now() + SETUP_TTL_MS);
    return `${exp}.${hmac(ctx.config.sessionSecret, `setup:${exp}:${sha256(ctx.config.bootstrapToken!)}`)}`;
  };
  const unlockValid = (value: string | undefined) => {
    if (!value) return false;
    const [exp, sig] = value.split('.');
    if (!exp || !sig || Number(exp) < Date.now()) return false;
    return safeEqual(hmac(ctx.config.sessionSecret, `setup:${exp}:${sha256(ctx.config.bootstrapToken!)}`), sig);
  };
  const readCookie = (req: Request) => {
    const m = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith(SETUP_COOKIE + '='));
    return m ? decodeURIComponent(m.slice(SETUP_COOKIE.length + 1)) : undefined;
  };

  r.get('/setup', gate, (_req, res) => res.render('setup/token', { title: 'First-time setup', error: null }));

  r.post(
    '/setup/token',
    limiter,
    gate,
    wrap(async (req, res) => {
      const token = String(req.body.token || '');
      if (!token || !safeEqual(token, ctx.config.bootstrapToken!)) {
        await audit(ctx, { actorType: 'anonymous', action: 'setup.token_rejected', ip: req.meta.ip, userAgent: req.meta.userAgent });
        // Same response as a missing page: do not confirm that setup exists to a guesser.
        return res.status(404).render('error', { title: 'Not found', status: 404, message: 'Page not found.' });
      }
      await audit(ctx, { actorType: 'anonymous', action: 'setup.token_accepted', ip: req.meta.ip, userAgent: req.meta.userAgent });
      res.cookie(SETUP_COOKIE, mintUnlock(), cookieOptions(ctx, SETUP_TTL_MS));
      res.redirect('/setup/admin');
    }),
  );

  r.get(
    '/setup/admin',
    gate,
    wrap(async (req, res) => {
      const unlock = readCookie(req);
      if (!unlockValid(unlock)) return res.redirect('/setup');
      res.render('setup/admin', { title: 'Create the first administrator', error: null, unlock, form: {} });
    }),
  );

  r.post(
    '/setup/admin',
    limiter,
    gate,
    wrap(async (req, res) => {
      const unlock = readCookie(req);
      // Double-submit: the unlock value must arrive both as the cookie and as a form field.
      if (!unlockValid(unlock) || String(req.body._setup || '') !== unlock) return res.redirect('/setup');
      const parsed = z.object({ email: z.string().trim().email().max(200), name: z.string().trim().min(1).max(200), password: z.string().max(500), confirm: z.string().max(500) }).safeParse(req.body);
      const fail = (error: string) => res.status(400).render('setup/admin', { title: 'Create the first administrator', error, unlock, form: req.body });
      if (!parsed.success) return fail('Enter your name, a valid email address and a password.');
      const { email, name, password, confirm } = parsed.data;
      if (password !== confirm) return fail('The passwords do not match.');
      const weak = validatePasswordStrength(password);
      if (weak) return fail(weak);

      // Create the admin and a password-only session in one transaction; the users-table guard is
      // re-checked inside it so two racing requests cannot both create an admin.
      let token: string;
      try {
        token = await ctx.db.tx(async (t) => {
          const count = await t.scalar<number>('SELECT COUNT(*) FROM users');
          if (count > 0) throw new HttpError(404, 'Page not found.');
          const tctx = { ...ctx, db: t };
          const user = await createUser(tctx, { email, name, role: 'admin', password }, null);
          const sessionToken = randomToken(32);
          await t.run(
            'INSERT INTO sessions (id, user_id, csrf_token, mfa_passed, expires_at, ip, user_agent, device_id) VALUES (?, ?, ?, false, ?, ?, ?, ?)',
            sha256(sessionToken),
            user.id,
            randomToken(24),
            new Date(Date.now() + 12 * 3600_000).toISOString(),
            req.meta.ip,
            req.meta.userAgent.slice(0, 500),
            req.meta.deviceId,
          );
          await audit(tctx, { actorType: 'system', actorLabel: 'bootstrap', action: 'setup.admin_created', entityType: 'user', entityId: user.id, details: { email: user.email }, ip: req.meta.ip, userAgent: req.meta.userAgent });
          return sessionToken;
        });
      } catch (err) {
        if (err instanceof HttpError) throw err;
        return fail((err as Error).message);
      }
      res.clearCookie(SETUP_COOKIE, { path: '/' });
      res.cookie(STAFF_COOKIE, token, cookieOptions(ctx));
      // Mandatory TOTP enrollment: QR code, manual key, then one-time backup codes.
      res.redirect('/mfa');
    }),
  );

  return r;
}
