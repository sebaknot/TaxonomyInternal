import { Router } from 'express';
import QRCode from 'qrcode';
import { z } from 'zod';
import type { AppContext } from '../context.js';
import { loginWithPassword, beginMfaEnrollment, completeMfaEnrollment, verifyMfaCode, completeLogin, logout, getMfaSecret, getUserById, changeOwnPassword, revokeOtherSessions } from '../services/auth.js';
import { otpauthUrl } from '../lib/totp.js';
import { STAFF_COOKIE, cookieOptions, requireAuth, wrap } from '../middleware/index.js';
import { dbRateLimit } from '../middleware/rateLimit.js';
import { audit } from '../services/audit.js';

function safeNext(next: unknown): string {
  return typeof next === 'string' && next.startsWith('/') && !next.startsWith('//') ? next : '/';
}

export function authRouter(ctx: AppContext) {
  const r = Router();
  const loginLimit = dbRateLimit(ctx, { name: 'login', windowMs: 15 * 60_000, max: 30 });
  const mfaLimit = dbRateLimit(ctx, { name: 'mfa', windowMs: 15 * 60_000, max: 30 });

  r.get('/login', (req, res) => {
    if (req.user) return res.redirect('/');
    if (req.staffSession) return res.redirect('/mfa');
    res.render('auth/login', { title: 'Sign in', next: safeNext(req.query.next), error: null });
  });

  r.post(
    '/login',
    loginLimit,
    wrap(async (req, res) => {
      const parsed = z.object({ email: z.string().email().max(200), password: z.string().min(1).max(500), next: z.string().optional() }).safeParse(req.body);
      if (!parsed.success) return res.status(400).render('auth/login', { title: 'Sign in', next: '/', error: 'Enter your email and password.' });
      const result = await loginWithPassword(req.ctx, parsed.data.email, parsed.data.password, req.meta);
      if (!result.ok) {
        const msg =
          result.reason === 'locked'
            ? 'Too many failed attempts. This account is temporarily locked.'
            : result.reason === 'revoked'
              ? 'This account has been deactivated. Contact an administrator.'
              : 'Invalid email or password.';
        return res.status(401).render('auth/login', { title: 'Sign in', next: safeNext(parsed.data.next), error: msg });
      }
      res.cookie(STAFF_COOKIE, result.sessionToken, cookieOptions(req.ctx));
      res.redirect('/mfa' + (parsed.data.next ? `?next=${encodeURIComponent(safeNext(parsed.data.next))}` : ''));
    }),
  );

  r.get(
    '/mfa',
    wrap(async (req, res) => {
      if (req.user) return res.redirect('/');
      if (!req.staffSession || !req.staffUser) return res.redirect('/login');
      const u = req.staffUser;
      if (u.mfa_enabled) return res.render('auth/mfa', { title: 'Two-factor verification', next: safeNext(req.query.next), error: null });
      const secret = getMfaSecret(req.ctx, u) ?? (await beginMfaEnrollment(req.ctx, u));
      const url = otpauthUrl(res.locals.firmName || 'Taxonomy', u.email, secret);
      const qr = await QRCode.toDataURL(url, { margin: 1, width: 220 });
      res.render('auth/mfa_setup', { title: 'Set up two-factor authentication', qr, secret, next: safeNext(req.query.next), error: null });
    }),
  );

  r.post(
    '/mfa',
    mfaLimit,
    wrap(async (req, res) => {
      if (!req.staffSession || !req.staffUser) return res.redirect('/login');
      const u = req.staffUser;
      const code = String(req.body.code || '');
      if (!u.mfa_enabled) return res.redirect('/mfa');
      if (!(await verifyMfaCode(req.ctx, u, code))) {
        await audit(req.ctx, { actorType: 'user', actorId: u.id, actorLabel: u.email, action: 'auth.mfa_failed', entityType: 'user', entityId: u.id, ip: req.meta.ip, userAgent: req.meta.userAgent });
        return res.status(401).render('auth/mfa', { title: 'Two-factor verification', next: safeNext(req.body.next), error: 'That code is not valid.' });
      }
      await completeLogin(req.ctx, req.staffSession.id, u, req.meta, /^\d{6}$/.test(code.trim()) ? 'totp' : 'backup_code');
      res.redirect(safeNext(req.body.next));
    }),
  );

  r.post(
    '/mfa/setup',
    mfaLimit,
    wrap(async (req, res) => {
      if (!req.staffSession || !req.staffUser) return res.redirect('/login');
      const u = req.staffUser;
      if (u.mfa_enabled) return res.redirect('/mfa');
      const result = await completeMfaEnrollment(req.ctx, u, String(req.body.code || ''), req.meta);
      if (!result.ok) {
        const secret = getMfaSecret(req.ctx, u)!;
        const qr = await QRCode.toDataURL(otpauthUrl(res.locals.firmName || 'Taxonomy', u.email, secret), { margin: 1, width: 220 });
        return res.status(400).render('auth/mfa_setup', { title: 'Set up two-factor authentication', qr, secret, next: safeNext(req.body.next), error: 'That code did not match. Scan the QR code again and enter the current code.' });
      }
      await completeLogin(req.ctx, req.staffSession.id, u, req.meta, 'enrollment');
      res.render('auth/backup_codes', { title: 'Backup codes', codes: result.backupCodes, next: safeNext(req.body.next) });
    }),
  );

  r.post(
    '/logout',
    wrap(async (req, res) => {
      if (req.staffSession && req.staffUser) await logout(req.ctx, req.staffSession, req.staffUser, req.meta);
      res.clearCookie(STAFF_COOKIE, { path: '/' });
      res.redirect('/login');
    }),
  );

  r.get(
    '/account',
    requireAuth,
    wrap(async (req, res) => {
      const sessions = await req.ctx.db.scalar<number>('SELECT COUNT(*) FROM sessions WHERE user_id = ? AND mfa_passed = true', req.user!.id);
      res.render('auth/account', { title: 'My account', sessions });
    }),
  );
  r.get('/account/password', requireAuth, (req, res) => {
    res.render('auth/password', { title: 'Change password', error: null, forced: !!req.staffUser?.must_change_password });
  });
  r.post(
    '/account/password',
    requireAuth,
    mfaLimit,
    wrap(async (req, res) => {
      const u = (await getUserById(req.ctx, req.user!.id))!;
      const b = req.body as Record<string, string>;
      try {
        await changeOwnPassword(req.ctx, u, req.staffSession!, { current: String(b.current || ''), password: String(b.password || ''), confirm: String(b.confirm || ''), totp: String(b.totp || '') }, req.meta);
      } catch (err) {
        return res.status(400).render('auth/password', { title: 'Change password', error: (err as Error).message, forced: !!u.must_change_password });
      }
      req.flash('success', 'Password changed. All other sessions were signed out and a confirmation email was sent.');
      res.redirect('/account');
    }),
  );
  r.post(
    '/account/sessions/revoke-others',
    requireAuth,
    wrap(async (req, res) => {
      const n = await revokeOtherSessions(req.ctx, req.staffUser!, req.staffSession!, req.meta);
      req.flash('success', n ? `Signed out of ${n} other session${n === 1 ? '' : 's'}.` : 'No other sessions were active.');
      res.redirect('/account');
    }),
  );

  return r;
}
