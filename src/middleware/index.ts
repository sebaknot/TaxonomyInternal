import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { AppContext } from '../context.js';
import { checkSession, type SessionRow, type UserRow, toSessionUser } from '../services/auth.js';
import { checkPortalSession, type PortalSessionRow, type MagicLinkRow } from '../services/magic.js';
import { hmac, randomToken, safeEqual } from '../lib/crypto.js';
import type { SessionUser } from '../services/permissions.js';
import { ROLE_LABELS } from '../lib/constants.js';
import { allSettings } from '../services/settings.js';

export const STAFF_COOKIE = 'tx_session';
export const PORTAL_COOKIE = 'tx_portal';
export const DEVICE_COOKIE = 'tx_device';

declare global {
  namespace Express {
    interface Request {
      ctx: AppContext;
      staffSession?: SessionRow;
      staffUser?: UserRow;
      user?: SessionUser; // set only when fully authenticated (password + MFA)
      portalSession?: PortalSessionRow;
      portalLink?: MagicLinkRow;
      meta: { ip: string; userAgent: string; deviceId: string };
      flash: (type: 'success' | 'error' | 'info', message: string) => void;
    }
  }
}

export class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

/** Wraps an async handler so rejections reach the error handler (Express 5 does this too; explicit for clarity/typing). */
export const wrap =
  (fn: (req: Request, res: Response, next: NextFunction) => Promise<unknown>): RequestHandler =>
  (req, res, next) => {
    fn(req, res, next).catch(next);
  };

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

export function cookieOptions(ctx: AppContext, maxAgeMs?: number) {
  return {
    httpOnly: true,
    secure: ctx.config.cookieSecure,
    sameSite: 'lax' as const, // 'lax' so links from email land on an authenticated page; state-changing routes are CSRF-protected
    path: '/',
    ...(maxAgeMs ? { maxAge: maxAgeMs } : {}),
  };
}

/**
 * Attaches ctx, request metadata (ip, UA, signed device id), a cookie-backed flash, and loads
 * whichever session cookie is present from the database. Holds no in-memory state, so it is
 * safe across serverless invocations.
 */
export function baseMiddleware(ctx: AppContext): RequestHandler {
  return wrap(async (req, res, next) => {
    req.ctx = ctx;
    const cookies = parseCookies(req.headers.cookie);

    let deviceId = '';
    const raw = cookies[DEVICE_COOKIE];
    if (raw) {
      const [id, sig] = raw.split('.');
      if (id && sig && safeEqual(hmac(ctx.config.sessionSecret, id), sig)) deviceId = id;
    }
    if (!deviceId) {
      deviceId = randomToken(16);
      res.cookie(DEVICE_COOKIE, `${deviceId}.${hmac(ctx.config.sessionSecret, deviceId)}`, cookieOptions(ctx, 365 * 24 * 3600_000));
    }
    req.meta = { ip: req.ip || req.socket.remoteAddress || '', userAgent: String(req.headers['user-agent'] || ''), deviceId };

    const flashes: { type: string; message: string }[] = [];
    if (cookies.tx_flash) {
      try {
        flashes.push(...JSON.parse(cookies.tx_flash));
      } catch {}
      res.clearCookie('tx_flash', { path: '/' });
    }
    const pending: { type: string; message: string }[] = [];
    req.flash = (type, message) => {
      pending.push({ type, message });
      res.cookie('tx_flash', JSON.stringify(pending), { ...cookieOptions(ctx), maxAge: 60_000 });
    };

    const check = await checkSession(ctx, cookies[STAFF_COOKIE]);
    if (check.status === 'ok') {
      req.staffSession = check.session;
      req.staffUser = check.user;
      if (check.session.mfa_passed) req.user = toSessionUser(check.user);
    } else if (check.status !== 'none') {
      res.clearCookie(STAFF_COOKIE, { path: '/' });
      if (check.status === 'idle') flashes.push({ type: 'info', message: 'You were signed out after a period of inactivity.' });
      else if (check.status === 'revoked') flashes.push({ type: 'error', message: 'Your access has been revoked. Contact an administrator.' });
      else flashes.push({ type: 'info', message: 'Your session expired. Please sign in again.' });
    }
    const pcheck = await checkPortalSession(ctx, cookies[PORTAL_COOKIE]);
    if (pcheck.status === 'ok') {
      req.portalSession = pcheck.session;
      req.portalLink = pcheck.link;
    } else if (pcheck.status !== 'none') res.clearCookie(PORTAL_COOKIE, { path: '/' });

    const settings = await allSettings(ctx);
    res.locals.user = req.user ?? null;
    res.locals.flashes = flashes;
    res.locals.roleLabels = ROLE_LABELS;
    res.locals.firmName = settings.firm_name;
    res.locals.settings = settings;
    res.locals.csrfToken = req.staffSession?.csrf_token ?? req.portalSession?.csrf_token ?? '';
    res.locals.currentPath = req.path;
    next();
  });
}

/** Requires a fully authenticated staff user (password + MFA). */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (req.user) return next();
  if (req.staffSession && !req.staffSession.mfa_passed) return res.redirect('/mfa');
  if (req.accepts(['html', 'json']) === 'json') return res.status(401).json({ error: 'Sign in required' });
  const nextUrl = req.method === 'GET' ? `?next=${encodeURIComponent(req.originalUrl)}` : '';
  return res.redirect('/login' + nextUrl);
}

export function requireRole(pred: (u: SessionUser) => boolean): RequestHandler {
  return (req, _res, next) => {
    if (!req.user) return next(new HttpError(401, 'Sign in required'));
    if (!pred(req.user)) return next(new HttpError(403, 'You do not have permission to do that.'));
    next();
  };
}

export function csrfValid(req: Request): boolean {
  const expected = req.staffSession?.csrf_token ?? req.portalSession?.csrf_token;
  if (!expected) return true; // unauthenticated POSTs (login) are rate limited and have no session to ride
  const provided = (req.body && req.body._csrf) || req.headers['x-csrf-token'];
  return typeof provided === 'string' && safeEqual(provided, expected);
}
export function csrfProtection(req: Request, _res: Response, next: NextFunction) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  // Multipart bodies are parsed later by multer; those routes call csrfAfterUpload themselves.
  if ((req.headers['content-type'] || '').startsWith('multipart/form-data')) return next();
  if (!csrfValid(req)) return next(new HttpError(403, 'Invalid or missing CSRF token. Please reload the page and try again.'));
  next();
}
/** For multer routes: verify the token that arrived inside the multipart body. */
export function csrfAfterUpload(req: Request, _res: Response, next: NextFunction) {
  if (csrfValid(req)) return next();
  next(new HttpError(403, 'Invalid or missing CSRF token. Please reload the page and try again.'));
}

export function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction) {
  const status = err instanceof HttpError ? err.status : (err as any)?.status || 500;
  const message = err instanceof HttpError ? err.message : status === 500 ? 'Something went wrong.' : (err as Error).message;
  if (status >= 500) console.error(err);
  if (res.headersSent) return;
  if (req.accepts(['html', 'json']) === 'json') return res.status(status).json({ error: message });
  res.status(status).render('error', { title: `Error ${status}`, status, message });
}
