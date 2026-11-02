import type { AppContext } from '../context.js';
import { hashPassword, verifyPassword, randomToken, sha256, newId, safeEqual } from '../lib/crypto.js';
import { generateTotpSecret, verifyTotp } from '../lib/totp.js';
import { audit } from './audit.js';
import { getSettingInt } from './settings.js';
import { SETTING_KEYS, type Role } from '../lib/constants.js';
import type { SessionUser } from './permissions.js';

export interface UserRow {
  id: string;
  email: string;
  name: string;
  role: Role;
  password_hash: string;
  mfa_secret_enc: string | null;
  mfa_enabled: boolean;
  backup_codes: string | null;
  is_active: boolean;
  revoked_at: string | null;
  failed_login_count: number;
  locked_until: string | null;
  created_at: string;
  updated_at: string;
}

export interface SessionRow {
  id: string;
  user_id: string;
  csrf_token: string;
  mfa_passed: boolean;
  created_at: string;
  last_activity_at: string;
  expires_at: string;
  ip: string | null;
  user_agent: string | null;
  device_id: string | null;
}

const SESSION_ABSOLUTE_HOURS = 12;
const MAX_FAILED_LOGINS = 5;
const LOCKOUT_MINUTES = 15;
const MIN_PASSWORD_LENGTH = 12;

export function validatePasswordStrength(pw: string): string | null {
  if (pw.length < MIN_PASSWORD_LENGTH) return `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
  if (!/[A-Za-z]/.test(pw) || !/[0-9]/.test(pw)) return 'Password must contain letters and numbers.';
  return null;
}

// ---------- Users ----------

export function getUserById(ctx: AppContext, id: string) {
  return ctx.db.one<UserRow>('SELECT * FROM users WHERE id = ?', id);
}
export function getUserByEmail(ctx: AppContext, email: string) {
  return ctx.db.one<UserRow>('SELECT * FROM users WHERE lower(email) = lower(?)', email.trim());
}
export function listUsers(ctx: AppContext) {
  return ctx.db.all<UserRow>('SELECT * FROM users ORDER BY is_active DESC, name');
}
export function listActiveUsersByRole(ctx: AppContext, roles: Role[]) {
  return ctx.db.all<UserRow>(`SELECT * FROM users WHERE is_active = true AND role = ANY(?) ORDER BY name`, roles);
}

export async function createUser(ctx: AppContext, input: { email: string; name: string; role: Role; password: string }, actor?: SessionUser | null): Promise<UserRow> {
  const pwErr = validatePasswordStrength(input.password);
  if (pwErr) throw new Error(pwErr);
  if (await getUserByEmail(ctx, input.email)) throw new Error('A user with that email already exists.');
  const id = newId();
  await ctx.db.run('INSERT INTO users (id, email, name, role, password_hash) VALUES (?, ?, ?, ?, ?)', id, input.email.trim().toLowerCase(), input.name.trim(), input.role, hashPassword(input.password));
  await audit(ctx, {
    actorType: actor ? 'user' : 'system',
    actorId: actor?.id,
    actorLabel: actor?.email ?? 'cli',
    action: 'user.create',
    entityType: 'user',
    entityId: id,
    details: { email: input.email, role: input.role },
  });
  return (await getUserById(ctx, id))!;
}

export async function updateUser(ctx: AppContext, id: string, patch: { name?: string; role?: Role; email?: string }, actor: SessionUser) {
  const u = await getUserById(ctx, id);
  if (!u) throw new Error('User not found');
  await ctx.db.run('UPDATE users SET name = ?, role = ?, email = ?, updated_at = now() WHERE id = ?', patch.name ?? u.name, patch.role ?? u.role, (patch.email ?? u.email).trim().toLowerCase(), id);
  await audit(ctx, { actorType: 'user', actorId: actor.id, actorLabel: actor.email, action: 'user.update', entityType: 'user', entityId: id, details: patch });
}

export async function setUserPassword(ctx: AppContext, id: string, password: string, actor: SessionUser | null) {
  const pwErr = validatePasswordStrength(password);
  if (pwErr) throw new Error(pwErr);
  await ctx.db.tx(async (t) => {
    await t.run('UPDATE users SET password_hash = ?, updated_at = now() WHERE id = ?', hashPassword(password), id);
    // Password change invalidates all sessions for that user.
    await t.run('DELETE FROM sessions WHERE user_id = ?', id);
  });
  await audit(ctx, { actorType: actor ? 'user' : 'system', actorId: actor?.id, actorLabel: actor?.email ?? 'cli', action: 'user.password_reset', entityType: 'user', entityId: id });
}

/** Instantly revoke one user's access: deactivates the account and kills every live session. */
export async function revokeUser(ctx: AppContext, id: string, actor: SessionUser, ip?: string) {
  await ctx.db.tx(async (t) => {
    await t.run('UPDATE users SET is_active = false, revoked_at = now(), revoked_by = ?, updated_at = now() WHERE id = ?', actor.id, id);
    await t.run('DELETE FROM sessions WHERE user_id = ?', id);
  });
  await audit(ctx, { actorType: 'user', actorId: actor.id, actorLabel: actor.email, action: 'user.revoke', entityType: 'user', entityId: id, ip });
}
export async function reinstateUser(ctx: AppContext, id: string, actor: SessionUser, ip?: string) {
  await ctx.db.run('UPDATE users SET is_active = true, revoked_at = NULL, revoked_by = NULL, failed_login_count = 0, locked_until = NULL, updated_at = now() WHERE id = ?', id);
  await audit(ctx, { actorType: 'user', actorId: actor.id, actorLabel: actor.email, action: 'user.reinstate', entityType: 'user', entityId: id, ip });
}
/** Force re-enrollment of MFA (e.g. lost phone). Kills sessions so the next login must re-enroll. */
export async function resetUserMfa(ctx: AppContext, id: string, actor: SessionUser, ip?: string) {
  await ctx.db.tx(async (t) => {
    await t.run('UPDATE users SET mfa_secret_enc = NULL, mfa_enabled = false, backup_codes = NULL, updated_at = now() WHERE id = ?', id);
    await t.run('DELETE FROM sessions WHERE user_id = ?', id);
  });
  await audit(ctx, { actorType: 'user', actorId: actor.id, actorLabel: actor.email, action: 'user.mfa_reset', entityType: 'user', entityId: id, ip });
}

export function toSessionUser(u: UserRow): SessionUser {
  return { id: u.id, email: u.email, name: u.name, role: u.role };
}

// ---------- Login (step 1: password) ----------

export interface RequestMeta {
  ip?: string;
  userAgent?: string;
  deviceId?: string;
}

export type LoginResult = { ok: true; user: UserRow; sessionToken: string } | { ok: false; reason: 'invalid' | 'locked' | 'revoked' };

/**
 * Password step. Failure counters and lockouts live on the users row, so they are shared by
 * every serverless instance.
 */
export async function loginWithPassword(ctx: AppContext, email: string, password: string, meta: RequestMeta): Promise<LoginResult> {
  const user = await getUserByEmail(ctx, email);
  const fail = async (reason: 'invalid' | 'locked' | 'revoked', details?: Record<string, unknown>) => {
    await audit(ctx, {
      actorType: 'anonymous',
      actorLabel: email,
      actorId: user?.id,
      action: 'auth.login_failed',
      entityType: 'user',
      entityId: user?.id,
      details: { reason, ...details },
      ip: meta.ip,
      userAgent: meta.userAgent,
    });
    return { ok: false as const, reason };
  };
  if (!user) {
    // Burn comparable time so a missing account is not distinguishable by latency.
    verifyPassword(password, 'scrypt$32768$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
    return fail('invalid');
  }
  if (!user.is_active) return fail('revoked');
  if (user.locked_until && new Date(user.locked_until) > new Date()) return fail('locked');
  if (!verifyPassword(password, user.password_hash)) {
    // Atomic increment; lock when the threshold is reached.
    const row = await ctx.db.one<{ failed_login_count: number }>('UPDATE users SET failed_login_count = failed_login_count + 1 WHERE id = ? RETURNING failed_login_count', user.id);
    let lock: string | null = null;
    if ((row?.failed_login_count ?? 0) >= MAX_FAILED_LOGINS) {
      lock = new Date(Date.now() + LOCKOUT_MINUTES * 60_000).toISOString();
      await ctx.db.run('UPDATE users SET failed_login_count = 0, locked_until = ? WHERE id = ?', lock, user.id);
    }
    return fail('invalid', lock ? { lockedUntil: lock } : undefined);
  }
  await ctx.db.run('UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = ?', user.id);

  // Password OK: create a session that is NOT yet MFA-verified. Nothing but the MFA step is reachable with it.
  const token = randomToken(32);
  const expires = new Date(Date.now() + SESSION_ABSOLUTE_HOURS * 3600_000).toISOString();
  await ctx.db.run(
    'INSERT INTO sessions (id, user_id, csrf_token, mfa_passed, expires_at, ip, user_agent, device_id) VALUES (?, ?, ?, false, ?, ?, ?, ?)',
    sha256(token),
    user.id,
    randomToken(24),
    expires,
    meta.ip ?? null,
    meta.userAgent?.slice(0, 500) ?? null,
    meta.deviceId ?? null,
  );
  await audit(ctx, { actorType: 'user', actorId: user.id, actorLabel: user.email, action: 'auth.password_ok', entityType: 'user', entityId: user.id, ip: meta.ip, userAgent: meta.userAgent });
  return { ok: true, user, sessionToken: token };
}

// ---------- MFA ----------

export async function beginMfaEnrollment(ctx: AppContext, user: UserRow): Promise<string> {
  const secret = generateTotpSecret();
  await ctx.db.run('UPDATE users SET mfa_secret_enc = ? WHERE id = ?', ctx.cipher.encrypt(secret, `mfa:${user.id}`), user.id);
  return secret;
}
export function getMfaSecret(ctx: AppContext, user: UserRow): string | null {
  if (!user.mfa_secret_enc) return null;
  return ctx.cipher.decrypt(user.mfa_secret_enc, `mfa:${user.id}`);
}
export async function completeMfaEnrollment(ctx: AppContext, user: UserRow, code: string, meta: RequestMeta): Promise<{ ok: boolean; backupCodes?: string[] }> {
  const secret = getMfaSecret(ctx, user);
  if (!secret || !verifyTotp(secret, code)) {
    await audit(ctx, { actorType: 'user', actorId: user.id, actorLabel: user.email, action: 'auth.mfa_enroll_failed', entityType: 'user', entityId: user.id, ip: meta.ip, userAgent: meta.userAgent });
    return { ok: false };
  }
  const backupCodes = Array.from({ length: 8 }, () => randomToken(6).replace(/[-_]/g, 'x').slice(0, 8).toLowerCase());
  await ctx.db.run('UPDATE users SET mfa_enabled = true, backup_codes = ?, updated_at = now() WHERE id = ?', JSON.stringify(backupCodes.map((c) => sha256(c))), user.id);
  await audit(ctx, { actorType: 'user', actorId: user.id, actorLabel: user.email, action: 'auth.mfa_enrolled', entityType: 'user', entityId: user.id, ip: meta.ip, userAgent: meta.userAgent });
  return { ok: true, backupCodes };
}

/** Verify a TOTP code or a one-time backup code for a logged-in (password) session. */
export async function verifyMfaCode(ctx: AppContext, user: UserRow, code: string): Promise<boolean> {
  const secret = getMfaSecret(ctx, user);
  if (secret && verifyTotp(secret, code)) return true;
  const normalized = code.trim().toLowerCase();
  if (/^[a-z0-9]{8}$/.test(normalized) && user.backup_codes) {
    const hashes: string[] = JSON.parse(user.backup_codes);
    const h = sha256(normalized);
    const idx = hashes.findIndex((x) => safeEqual(x, h));
    if (idx >= 0) {
      hashes.splice(idx, 1);
      // Only consume the code if nobody else consumed it concurrently.
      const n = await ctx.db.run('UPDATE users SET backup_codes = ? WHERE id = ? AND backup_codes = ?', JSON.stringify(hashes), user.id, user.backup_codes);
      return n === 1;
    }
  }
  return false;
}

/** Marks the session fully authenticated, records device/location, and raises alerts for unknown ones. */
export async function completeLogin(ctx: AppContext, sessionId: string, user: UserRow, meta: RequestMeta, method: 'totp' | 'backup_code' | 'enrollment') {
  await ctx.db.run('UPDATE sessions SET mfa_passed = true, last_activity_at = now() WHERE id = ?', sessionId);
  await audit(ctx, { actorType: 'user', actorId: user.id, actorLabel: user.email, action: 'auth.login', entityType: 'user', entityId: user.id, details: { method }, ip: meta.ip, userAgent: meta.userAgent });

  const alerts: string[] = [];
  if (meta.deviceId) {
    const inserted = await ctx.db.run(
      `INSERT INTO user_devices (user_id, device_id, user_agent) VALUES (?, ?, ?) ON CONFLICT (user_id, device_id) DO NOTHING`,
      user.id,
      meta.deviceId,
      meta.userAgent?.slice(0, 500) ?? null,
    );
    if (inserted === 1) alerts.push('new_device');
    else await ctx.db.run('UPDATE user_devices SET last_seen_at = now(), user_agent = ? WHERE user_id = ? AND device_id = ?', meta.userAgent?.slice(0, 500) ?? null, user.id, meta.deviceId);
  }
  if (meta.ip) {
    const inserted = await ctx.db.run(`INSERT INTO user_locations (user_id, ip) VALUES (?, ?) ON CONFLICT (user_id, ip) DO NOTHING`, user.id, meta.ip);
    if (inserted === 1) alerts.push('new_location');
    else await ctx.db.run('UPDATE user_locations SET last_seen_at = now() WHERE user_id = ? AND ip = ?', user.id, meta.ip);
  }
  const loginCount = await ctx.db.scalar<number>("SELECT COUNT(*) FROM audit_log WHERE actor_id = ? AND action = 'auth.login'", user.id);
  const isFirstLogin = loginCount <= 1;
  if (alerts.length) {
    const message = `${user.name} (${user.email}) logged in from ${alerts.includes('new_device') ? 'a new device' : ''}${alerts.length === 2 ? ' and ' : ''}${alerts.includes('new_location') ? 'an unrecognized location (IP ' + meta.ip + ')' : ''}${isFirstLogin ? ' [first login]' : ''}`;
    await raiseAdminAlert(ctx, 'login_new_device_or_location', message, { userId: user.id, alerts, ip: meta.ip, userAgent: meta.userAgent, firstLogin: isFirstLogin }, user.id);
  }
}

export async function raiseAdminAlert(ctx: AppContext, type: string, message: string, details: Record<string, unknown>, userId?: string) {
  await ctx.db.run('INSERT INTO admin_alerts (id, type, user_id, message, details) VALUES (?, ?, ?, ?, ?)', newId(), type, userId ?? null, message, JSON.stringify(details));
  const admins = await ctx.db.all<{ email: string }>("SELECT email FROM users WHERE role = 'admin' AND is_active = true");
  for (const a of admins) {
    await ctx.mailer.send(a.email, `[Taxonomy] Security alert: ${type.replace(/_/g, ' ')}`, `${message}\n\nDetails: ${JSON.stringify(details, null, 2)}\n\nReview at ${ctx.config.baseUrl}/admin/alerts`);
  }
}

// ---------- Sessions ----------

export function sqlDateMs(v: string): number {
  return new Date(v.includes('T') ? v : v.replace(' ', 'T') + 'Z').getTime();
}

export function getSession(ctx: AppContext, token: string) {
  return ctx.db.one<SessionRow>('SELECT * FROM sessions WHERE id = ?', sha256(token));
}

export type SessionCheck = { status: 'ok'; session: SessionRow; user: UserRow } | { status: 'none' | 'expired' | 'idle' | 'revoked' };

/** Validates a session token against absolute expiry, idle timeout and user status; touches activity. */
export async function checkSession(ctx: AppContext, token: string | undefined): Promise<SessionCheck> {
  if (!token) return { status: 'none' };
  const s = await getSession(ctx, token);
  if (!s) return { status: 'none' };
  const now = Date.now();
  if (new Date(s.expires_at).getTime() < now) {
    await destroySession(ctx, s.id);
    return { status: 'expired' };
  }
  const idleMinutes = await getSettingInt(ctx, SETTING_KEYS.sessionIdleMinutes);
  if (now - sqlDateMs(s.last_activity_at) > idleMinutes * 60_000) {
    await destroySession(ctx, s.id);
    const u = await getUserById(ctx, s.user_id);
    await audit(ctx, { actorType: 'user', actorId: s.user_id, actorLabel: u?.email, action: 'auth.logout', entityType: 'user', entityId: s.user_id, details: { reason: 'idle_timeout', idleMinutes } });
    return { status: 'idle' };
  }
  const user = await getUserById(ctx, s.user_id);
  if (!user || !user.is_active) {
    await destroySession(ctx, s.id);
    return { status: 'revoked' };
  }
  await ctx.db.run('UPDATE sessions SET last_activity_at = now() WHERE id = ?', s.id);
  return { status: 'ok', session: s, user };
}

export async function destroySession(ctx: AppContext, sessionId: string) {
  await ctx.db.run('DELETE FROM sessions WHERE id = ?', sessionId);
}
export async function logout(ctx: AppContext, session: SessionRow, user: UserRow, meta: RequestMeta) {
  await destroySession(ctx, session.id);
  await audit(ctx, { actorType: 'user', actorId: user.id, actorLabel: user.email, action: 'auth.logout', entityType: 'user', entityId: user.id, details: { reason: 'user' }, ip: meta.ip, userAgent: meta.userAgent });
}
