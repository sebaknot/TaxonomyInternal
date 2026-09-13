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
  mfa_enabled: number;
  backup_codes: string | null;
  is_active: number;
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
  mfa_passed: number;
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

export function getUserById(ctx: AppContext, id: string): UserRow | undefined {
  return ctx.db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
}
export function getUserByEmail(ctx: AppContext, email: string): UserRow | undefined {
  return ctx.db.prepare('SELECT * FROM users WHERE email = ?').get(email.trim()) as UserRow | undefined;
}
export function listUsers(ctx: AppContext): UserRow[] {
  return ctx.db.prepare('SELECT * FROM users ORDER BY is_active DESC, name').all() as UserRow[];
}
export function listActiveUsersByRole(ctx: AppContext, roles: Role[]): UserRow[] {
  const q = roles.map(() => '?').join(',');
  return ctx.db.prepare(`SELECT * FROM users WHERE is_active = 1 AND role IN (${q}) ORDER BY name`).all(...roles) as UserRow[];
}

export function createUser(
  ctx: AppContext,
  input: { email: string; name: string; role: Role; password: string },
  actor?: SessionUser | null,
): UserRow {
  const pwErr = validatePasswordStrength(input.password);
  if (pwErr) throw new Error(pwErr);
  if (getUserByEmail(ctx, input.email)) throw new Error('A user with that email already exists.');
  const id = newId();
  ctx.db
    .prepare('INSERT INTO users (id, email, name, role, password_hash) VALUES (?, ?, ?, ?, ?)')
    .run(id, input.email.trim().toLowerCase(), input.name.trim(), input.role, hashPassword(input.password));
  audit(ctx, {
    actorType: actor ? 'user' : 'system',
    actorId: actor?.id,
    actorLabel: actor?.email ?? 'cli',
    action: 'user.create',
    entityType: 'user',
    entityId: id,
    details: { email: input.email, role: input.role },
  });
  return getUserById(ctx, id)!;
}

export function updateUser(ctx: AppContext, id: string, patch: { name?: string; role?: Role; email?: string }, actor: SessionUser) {
  const u = getUserById(ctx, id);
  if (!u) throw new Error('User not found');
  ctx.db
    .prepare("UPDATE users SET name = ?, role = ?, email = ?, updated_at = datetime('now') WHERE id = ?")
    .run(patch.name ?? u.name, patch.role ?? u.role, (patch.email ?? u.email).trim().toLowerCase(), id);
  audit(ctx, { actorType: 'user', actorId: actor.id, actorLabel: actor.email, action: 'user.update', entityType: 'user', entityId: id, details: patch });
}

export function setUserPassword(ctx: AppContext, id: string, password: string, actor: SessionUser | null) {
  const pwErr = validatePasswordStrength(password);
  if (pwErr) throw new Error(pwErr);
  ctx.db.prepare("UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?").run(hashPassword(password), id);
  // Password change invalidates all other sessions for that user.
  ctx.db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
  audit(ctx, { actorType: actor ? 'user' : 'system', actorId: actor?.id, actorLabel: actor?.email ?? 'cli', action: 'user.password_reset', entityType: 'user', entityId: id });
}

/** Instantly revoke one user's access: deactivates the account and kills every live session. */
export function revokeUser(ctx: AppContext, id: string, actor: SessionUser, ip?: string) {
  ctx.db.transaction(() => {
    ctx.db.prepare("UPDATE users SET is_active = 0, revoked_at = datetime('now'), revoked_by = ?, updated_at = datetime('now') WHERE id = ?").run(actor.id, id);
    ctx.db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
  })();
  audit(ctx, { actorType: 'user', actorId: actor.id, actorLabel: actor.email, action: 'user.revoke', entityType: 'user', entityId: id, ip });
}
export function reinstateUser(ctx: AppContext, id: string, actor: SessionUser, ip?: string) {
  ctx.db
    .prepare("UPDATE users SET is_active = 1, revoked_at = NULL, revoked_by = NULL, failed_login_count = 0, locked_until = NULL, updated_at = datetime('now') WHERE id = ?")
    .run(id);
  audit(ctx, { actorType: 'user', actorId: actor.id, actorLabel: actor.email, action: 'user.reinstate', entityType: 'user', entityId: id, ip });
}
/** Force re-enrollment of MFA (e.g. lost phone). Kills sessions so the next login must re-enroll. */
export function resetUserMfa(ctx: AppContext, id: string, actor: SessionUser, ip?: string) {
  ctx.db.transaction(() => {
    ctx.db.prepare("UPDATE users SET mfa_secret_enc = NULL, mfa_enabled = 0, backup_codes = NULL, updated_at = datetime('now') WHERE id = ?").run(id);
    ctx.db.prepare('DELETE FROM sessions WHERE user_id = ?').run(id);
  })();
  audit(ctx, { actorType: 'user', actorId: actor.id, actorLabel: actor.email, action: 'user.mfa_reset', entityType: 'user', entityId: id, ip });
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

export type LoginResult =
  | { ok: true; user: UserRow; sessionToken: string }
  | { ok: false; reason: 'invalid' | 'locked' | 'revoked' };

export function loginWithPassword(ctx: AppContext, email: string, password: string, meta: RequestMeta): LoginResult {
  const user = getUserByEmail(ctx, email);
  const fail = (reason: 'invalid' | 'locked' | 'revoked', details?: Record<string, unknown>) => {
    audit(ctx, {
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
    const count = user.failed_login_count + 1;
    const lock = count >= MAX_FAILED_LOGINS ? new Date(Date.now() + LOCKOUT_MINUTES * 60_000).toISOString() : null;
    ctx.db.prepare('UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?').run(lock ? 0 : count, lock, user.id);
    return fail('invalid', lock ? { lockedUntil: lock } : undefined);
  }
  ctx.db.prepare('UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = ?').run(user.id);

  // Password OK: create a session that is NOT yet MFA-verified. Nothing but the MFA
  // step is reachable with it.
  const token = randomToken(32);
  const expires = new Date(Date.now() + SESSION_ABSOLUTE_HOURS * 3600_000).toISOString();
  ctx.db
    .prepare('INSERT INTO sessions (id, user_id, csrf_token, mfa_passed, expires_at, ip, user_agent, device_id) VALUES (?, ?, ?, 0, ?, ?, ?, ?)')
    .run(sha256(token), user.id, randomToken(24), expires, meta.ip ?? null, meta.userAgent?.slice(0, 500) ?? null, meta.deviceId ?? null);
  audit(ctx, { actorType: 'user', actorId: user.id, actorLabel: user.email, action: 'auth.password_ok', entityType: 'user', entityId: user.id, ip: meta.ip, userAgent: meta.userAgent });
  return { ok: true, user, sessionToken: token };
}

// ---------- MFA ----------

export function beginMfaEnrollment(ctx: AppContext, user: UserRow): string {
  // A pending secret is stored (encrypted) but mfa_enabled stays 0 until the user proves they have it.
  const secret = generateTotpSecret();
  ctx.db.prepare('UPDATE users SET mfa_secret_enc = ? WHERE id = ?').run(ctx.cipher.encrypt(secret, `mfa:${user.id}`), user.id);
  return secret;
}
export function getMfaSecret(ctx: AppContext, user: UserRow): string | null {
  if (!user.mfa_secret_enc) return null;
  return ctx.cipher.decrypt(user.mfa_secret_enc, `mfa:${user.id}`);
}
export function completeMfaEnrollment(ctx: AppContext, user: UserRow, code: string, meta: RequestMeta): { ok: boolean; backupCodes?: string[] } {
  const secret = getMfaSecret(ctx, user);
  if (!secret || !verifyTotp(secret, code)) {
    audit(ctx, { actorType: 'user', actorId: user.id, actorLabel: user.email, action: 'auth.mfa_enroll_failed', entityType: 'user', entityId: user.id, ip: meta.ip, userAgent: meta.userAgent });
    return { ok: false };
  }
  const backupCodes = Array.from({ length: 8 }, () => randomToken(6).replace(/[-_]/g, 'x').slice(0, 8).toLowerCase());
  ctx.db
    .prepare("UPDATE users SET mfa_enabled = 1, backup_codes = ?, updated_at = datetime('now') WHERE id = ?")
    .run(JSON.stringify(backupCodes.map((c) => sha256(c))), user.id);
  audit(ctx, { actorType: 'user', actorId: user.id, actorLabel: user.email, action: 'auth.mfa_enrolled', entityType: 'user', entityId: user.id, ip: meta.ip, userAgent: meta.userAgent });
  return { ok: true, backupCodes };
}

/** Verify a TOTP code or a one-time backup code for a logged-in (password) session. */
export function verifyMfaCode(ctx: AppContext, user: UserRow, code: string): boolean {
  const secret = getMfaSecret(ctx, user);
  if (secret && verifyTotp(secret, code)) return true;
  // Backup code?
  const normalized = code.trim().toLowerCase();
  if (/^[a-z0-9]{8}$/.test(normalized) && user.backup_codes) {
    const hashes: string[] = JSON.parse(user.backup_codes);
    const h = sha256(normalized);
    const idx = hashes.findIndex((x) => safeEqual(x, h));
    if (idx >= 0) {
      hashes.splice(idx, 1);
      ctx.db.prepare('UPDATE users SET backup_codes = ? WHERE id = ?').run(JSON.stringify(hashes), user.id);
      return true;
    }
  }
  return false;
}

/** Marks the session fully authenticated, records device/location, and raises alerts for unknown ones. */
export async function completeLogin(ctx: AppContext, sessionId: string, user: UserRow, meta: RequestMeta, method: 'totp' | 'backup_code' | 'enrollment') {
  ctx.db.prepare("UPDATE sessions SET mfa_passed = 1, last_activity_at = datetime('now') WHERE id = ?").run(sessionId);
  audit(ctx, { actorType: 'user', actorId: user.id, actorLabel: user.email, action: 'auth.login', entityType: 'user', entityId: user.id, details: { method }, ip: meta.ip, userAgent: meta.userAgent });

  const alerts: string[] = [];
  if (meta.deviceId) {
    const known = ctx.db.prepare('SELECT 1 FROM user_devices WHERE user_id = ? AND device_id = ?').get(user.id, meta.deviceId);
    ctx.db
      .prepare(
        `INSERT INTO user_devices (user_id, device_id, user_agent) VALUES (?, ?, ?)
         ON CONFLICT(user_id, device_id) DO UPDATE SET last_seen_at = datetime('now'), user_agent = excluded.user_agent`,
      )
      .run(user.id, meta.deviceId, meta.userAgent?.slice(0, 500) ?? null);
    if (!known) alerts.push('new_device');
  }
  if (meta.ip) {
    const known = ctx.db.prepare('SELECT 1 FROM user_locations WHERE user_id = ? AND ip = ?').get(user.id, meta.ip);
    ctx.db
      .prepare(`INSERT INTO user_locations (user_id, ip) VALUES (?, ?) ON CONFLICT(user_id, ip) DO UPDATE SET last_seen_at = datetime('now')`)
      .run(user.id, meta.ip);
    if (!known) alerts.push('new_location');
  }
  // First-ever login on a brand-new account is expected to be "new"; still record it, but flag as first login.
  const isFirstLogin = (ctx.db.prepare("SELECT COUNT(*) c FROM audit_log WHERE actor_id = ? AND action = 'auth.login'").get(user.id) as any).c <= 1;
  if (alerts.length) {
    const message = `${user.name} (${user.email}) logged in from ${alerts.includes('new_device') ? 'a new device' : ''}${alerts.length === 2 ? ' and ' : ''}${alerts.includes('new_location') ? 'an unrecognized location (IP ' + meta.ip + ')' : ''}${isFirstLogin ? ' [first login]' : ''}`;
    await raiseAdminAlert(ctx, 'login_new_device_or_location', message, { userId: user.id, alerts, ip: meta.ip, userAgent: meta.userAgent, firstLogin: isFirstLogin }, user.id);
  }
}

export async function raiseAdminAlert(ctx: AppContext, type: string, message: string, details: Record<string, unknown>, userId?: string) {
  ctx.db.prepare('INSERT INTO admin_alerts (id, type, user_id, message, details) VALUES (?, ?, ?, ?, ?)').run(newId(), type, userId ?? null, message, JSON.stringify(details));
  const admins = ctx.db.prepare("SELECT email FROM users WHERE role = 'admin' AND is_active = 1").all() as { email: string }[];
  for (const a of admins) {
    await ctx.mailer.send(a.email, `[Taxonomy] Security alert: ${type.replace(/_/g, ' ')}`, `${message}\n\nDetails: ${JSON.stringify(details, null, 2)}\n\nReview at ${ctx.config.baseUrl}/admin/alerts`);
  }
}

// ---------- Sessions ----------

/** SQLite datetime('now') yields 'YYYY-MM-DD HH:MM:SS' in UTC. */
export function sqlDateMs(v: string): number {
  return new Date(v.includes('T') ? v : v.replace(' ', 'T') + 'Z').getTime();
}

export function getSession(ctx: AppContext, token: string): SessionRow | undefined {
  return ctx.db.prepare('SELECT * FROM sessions WHERE id = ?').get(sha256(token)) as SessionRow | undefined;
}

export type SessionCheck = { status: 'ok'; session: SessionRow; user: UserRow } | { status: 'none' | 'expired' | 'idle' | 'revoked' };

/** Validates a session token against absolute expiry, idle timeout and user status; touches activity. */
export function checkSession(ctx: AppContext, token: string | undefined): SessionCheck {
  if (!token) return { status: 'none' };
  const s = getSession(ctx, token);
  if (!s) return { status: 'none' };
  const now = Date.now();
  if (new Date(s.expires_at).getTime() < now) {
    destroySession(ctx, s.id);
    return { status: 'expired' };
  }
  const idleMinutes = getSettingInt(ctx, SETTING_KEYS.sessionIdleMinutes);
  const lastActivity = sqlDateMs(s.last_activity_at);
  if (now - lastActivity > idleMinutes * 60_000) {
    destroySession(ctx, s.id);
    const u = getUserById(ctx, s.user_id);
    audit(ctx, { actorType: 'user', actorId: s.user_id, actorLabel: u?.email, action: 'auth.logout', entityType: 'user', entityId: s.user_id, details: { reason: 'idle_timeout', idleMinutes } });
    return { status: 'idle' };
  }
  const user = getUserById(ctx, s.user_id);
  if (!user || !user.is_active) {
    destroySession(ctx, s.id);
    return { status: 'revoked' };
  }
  ctx.db.prepare("UPDATE sessions SET last_activity_at = datetime('now') WHERE id = ?").run(s.id);
  return { status: 'ok', session: s, user };
}

export function destroySession(ctx: AppContext, sessionId: string) {
  ctx.db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
}
export function logout(ctx: AppContext, session: SessionRow, user: UserRow, meta: RequestMeta) {
  destroySession(ctx, session.id);
  audit(ctx, { actorType: 'user', actorId: user.id, actorLabel: user.email, action: 'auth.logout', entityType: 'user', entityId: user.id, details: { reason: 'user' }, ip: meta.ip, userAgent: meta.userAgent });
}
