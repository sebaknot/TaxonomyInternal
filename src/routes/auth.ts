import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import QRCode from 'qrcode';
import { z } from 'zod';
import { loginWithPassword, beginMfaEnrollment, completeMfaEnrollment, verifyMfaCode, completeLogin, logout, getMfaSecret, setUserPassword, getUserById } from '../services/auth.js';
import { verifyPassword } from '../lib/crypto.js';
import { otpauthUrl } from '../lib/totp.js';
import { STAFF_COOKIE, cookieOptions, requireAuth } from '../middleware/index.js';
import { audit } from '../services/audit.js';

const limiter = (max: number) =>
  rateLimit({ windowMs: 15 * 60_000, max, standardHeaders: true, legacyHeaders: false, message: 'Too many attempts. Try again in 15 minutes.' });

function safeNext(next: unknown): string {
  return typeof next === 'string' && next.startsWith('/') && !next.startsWith('//') ? next : '/';
}

export function authRouter() {
  const r = Router();

  r.get('/login', (req, res) => {
    if (req.user) return res.redirect('/');
    if (req.staffSession) return res.redirect('/mfa');
    res.render('auth/login', { title: 'Sign in', next: safeNext(req.query.next), error: null });
  });

  r.post('/login', limiter(30), (req, res) => {
    const parsed = z.object({ email: z.string().email().max(200), password: z.string().min(1).max(500), next: z.string().optional() }).safeParse(req.body);
    if (!parsed.success) return res.status(400).render('auth/login', { title: 'Sign in', next: '/', error: 'Enter your email and password.' });
    const result = loginWithPassword(req.ctx, parsed.data.email, parsed.data.password, req.meta);
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
  });

  // MFA step. Password session required; fully authenticated users are sent home.
  r.get('/mfa', async (req, res) => {
    if (req.user) return res.redirect('/');
    if (!req.staffSession || !req.staffUser) return res.redirect('/login');
    const u = req.staffUser;
    if (u.mfa_enabled) return res.render('auth/mfa', { title: 'Two-factor verification', next: safeNext(req.query.next), error: null });
    // Enrollment: MFA is mandatory, so a user without it cannot proceed until they enroll.
    const secret = getMfaSecret(req.ctx, u) ?? beginMfaEnrollment(req.ctx, u);
    const url = otpauthUrl(res.locals.firmName || 'Taxonomy', u.email, secret);
    const qr = await QRCode.toDataURL(url, { margin: 1, width: 220 });
    res.render('auth/mfa_setup', { title: 'Set up two-factor authentication', qr, secret, next: safeNext(req.query.next), error: null });
  });

  r.post('/mfa', limiter(30), async (req, res) => {
    if (!req.staffSession || !req.staffUser) return res.redirect('/login');
    const u = req.staffUser;
    const code = String(req.body.code || '');
    if (!u.mfa_enabled) return res.redirect('/mfa');
    if (!verifyMfaCode(req.ctx, u, code)) {
      audit(req.ctx, { actorType: 'user', actorId: u.id, actorLabel: u.email, action: 'auth.mfa_failed', entityType: 'user', entityId: u.id, ip: req.meta.ip, userAgent: req.meta.userAgent });
      return res.status(401).render('auth/mfa', { title: 'Two-factor verification', next: safeNext(req.body.next), error: 'That code is not valid.' });
    }
    await completeLogin(req.ctx, req.staffSession.id, u, req.meta, /^\d{6}$/.test(code.trim()) ? 'totp' : 'backup_code');
    res.redirect(safeNext(req.body.next));
  });

  r.post('/mfa/setup', limiter(30), async (req, res) => {
    if (!req.staffSession || !req.staffUser) return res.redirect('/login');
    const u = req.staffUser;
    if (u.mfa_enabled) return res.redirect('/mfa');
    const result = completeMfaEnrollment(req.ctx, u, String(req.body.code || ''), req.meta);
    if (!result.ok) {
      const secret = getMfaSecret(req.ctx, u)!;
      const qr = await QRCode.toDataURL(otpauthUrl(res.locals.firmName || 'Taxonomy', u.email, secret), { margin: 1, width: 220 });
      return res.status(400).render('auth/mfa_setup', { title: 'Set up two-factor authentication', qr, secret, next: safeNext(req.body.next), error: 'That code did not match. Scan the QR code again and enter the current code.' });
    }
    await completeLogin(req.ctx, req.staffSession.id, u, req.meta, 'enrollment');
    res.render('auth/backup_codes', { title: 'Backup codes', codes: result.backupCodes, next: safeNext(req.body.next) });
  });

  r.post('/logout', (req, res) => {
    if (req.staffSession && req.staffUser) logout(req.ctx, req.staffSession, req.staffUser, req.meta);
    res.clearCookie(STAFF_COOKIE, { path: '/' });
    res.redirect('/login');
  });

  r.get('/account', requireAuth, (req, res) => res.render('auth/account', { title: 'My account', error: null }));
  r.post('/account/password', requireAuth, (req, res) => {
    const u = getUserById(req.ctx, req.user!.id)!;
    const { current, password, confirm } = req.body as Record<string, string>;
    if (!verifyPassword(String(current || ''), u.password_hash)) return res.status(400).render('auth/account', { title: 'My account', error: 'Current password is incorrect.' });
    if (password !== confirm) return res.status(400).render('auth/account', { title: 'My account', error: 'New passwords do not match.' });
    try {
      setUserPassword(req.ctx, u.id, String(password), req.user!);
    } catch (err) {
      return res.status(400).render('auth/account', { title: 'My account', error: (err as Error).message });
    }
    res.clearCookie(STAFF_COOKIE, { path: '/' });
    req.flash('success', 'Password changed. Please sign in again.');
    res.redirect('/login');
  });

  return r;
}
