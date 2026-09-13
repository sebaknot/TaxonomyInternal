import type { AppContext } from '../context.js';
import { newId, randomToken, sha256, safeEqual } from '../lib/crypto.js';
import { audit } from './audit.js';
import { getSettingInt } from './settings.js';
import { SETTING_KEYS } from '../lib/constants.js';
import { getClient, normalizeDate, type ClientRow } from './clients.js';
import type { SessionUser } from './permissions.js';
import { sqlDateMs } from './auth.js';

export interface MagicLinkRow {
  id: string;
  token_hash: string;
  type: 'returning' | 'intake';
  client_id: string | null;
  tax_year: number;
  label: string | null;
  created_by: string;
  created_at: string;
  expires_at: string;
  verify_attempts: number;
  verified_at: string | null;
  completed_at: string | null;
  revoked_at: string | null;
  created_client_id: string | null;
}
export interface PortalSessionRow {
  id: string;
  magic_link_id: string;
  client_id: string | null;
  csrf_token: string;
  verified: number;
  intake_identity: string | null;
  created_at: string;
  last_activity_at: string;
  expires_at: string;
  ip: string | null;
}

const MAX_VERIFY_ATTEMPTS = 5;
const PORTAL_IDLE_MINUTES = 30;
const PORTAL_ABSOLUTE_HOURS = 4;

export function createMagicLink(
  ctx: AppContext,
  input: { type: 'returning' | 'intake'; clientId?: string | null; taxYear: number; label?: string | null },
  actor: SessionUser,
  ip?: string,
): { link: MagicLinkRow; url: string } {
  if (input.type === 'returning' && !input.clientId) throw new Error('Returning-client links require a client');
  const token = randomToken(32);
  const hours = getSettingInt(ctx, SETTING_KEYS.magicLinkHours);
  const id = newId();
  const expires = new Date(Date.now() + hours * 3600_000).toISOString();
  ctx.db
    .prepare('INSERT INTO magic_links (id, token_hash, type, client_id, tax_year, label, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, sha256(token), input.type, input.clientId ?? null, input.taxYear, input.label ?? null, actor.id, expires);
  audit(ctx, {
    actorType: 'user',
    actorId: actor.id,
    actorLabel: actor.email,
    action: input.type === 'returning' ? 'magic_link.create_returning' : 'magic_link.create_intake',
    entityType: 'magic_link',
    entityId: id,
    clientId: input.clientId ?? null,
    details: { tax_year: input.taxYear, expires_at: expires, label: input.label },
    ip,
  });
  const url = `${ctx.config.baseUrl}/portal/${input.type === 'returning' ? 'r' : 'new'}/${token}`;
  return { link: getMagicLink(ctx, id)!, url };
}

export function getMagicLink(ctx: AppContext, id: string): MagicLinkRow | undefined {
  return ctx.db.prepare('SELECT * FROM magic_links WHERE id = ?').get(id) as MagicLinkRow | undefined;
}
export function findMagicLinkByToken(ctx: AppContext, token: string): MagicLinkRow | undefined {
  return ctx.db.prepare('SELECT * FROM magic_links WHERE token_hash = ?').get(sha256(token)) as MagicLinkRow | undefined;
}
export function listMagicLinksForClient(ctx: AppContext, clientId: string): (MagicLinkRow & { creator: string })[] {
  return ctx.db.prepare('SELECT m.*, u.name creator FROM magic_links m JOIN users u ON u.id = m.created_by WHERE m.client_id = ? ORDER BY m.created_at DESC').all(clientId) as any;
}
export function listIntakeLinks(ctx: AppContext): (MagicLinkRow & { creator: string; created_client_name: string | null })[] {
  return ctx.db
    .prepare(
      `SELECT m.*, u.name creator, c.legal_name created_client_name FROM magic_links m JOIN users u ON u.id = m.created_by
       LEFT JOIN clients c ON c.id = m.created_client_id WHERE m.type = 'intake' ORDER BY m.created_at DESC LIMIT 200`,
    )
    .all() as any;
}
export function revokeMagicLink(ctx: AppContext, link: MagicLinkRow, actor: SessionUser, ip?: string) {
  ctx.db.transaction(() => {
    ctx.db.prepare("UPDATE magic_links SET revoked_at = datetime('now') WHERE id = ?").run(link.id);
    ctx.db.prepare('DELETE FROM portal_sessions WHERE magic_link_id = ?').run(link.id);
  })();
  audit(ctx, { actorType: 'user', actorId: actor.id, actorLabel: actor.email, action: 'magic_link.revoke', entityType: 'magic_link', entityId: link.id, clientId: link.client_id, ip });
}

export type LinkState = 'valid' | 'expired' | 'revoked' | 'locked' | 'completed';
export function linkState(link: MagicLinkRow): LinkState {
  if (link.revoked_at) return 'revoked';
  if (link.verify_attempts >= MAX_VERIFY_ATTEMPTS) return 'locked';
  if (new Date(link.expires_at).getTime() < Date.now()) return 'expired';
  if (link.type === 'intake' && link.completed_at) return 'completed';
  return 'valid';
}

// ---------- Portal sessions ----------

export function createPortalSession(ctx: AppContext, link: MagicLinkRow, ip?: string): string {
  const token = randomToken(32);
  const expires = new Date(Math.min(Date.now() + PORTAL_ABSOLUTE_HOURS * 3600_000, new Date(link.expires_at).getTime() + PORTAL_ABSOLUTE_HOURS * 3600_000)).toISOString();
  ctx.db
    .prepare('INSERT INTO portal_sessions (id, magic_link_id, client_id, csrf_token, verified, expires_at, ip) VALUES (?, ?, ?, ?, 0, ?, ?)')
    .run(sha256(token), link.id, link.client_id, randomToken(24), expires, ip ?? null);
  return token;
}

export type PortalCheck = { status: 'ok'; session: PortalSessionRow; link: MagicLinkRow } | { status: 'none' | 'expired' | 'invalid' };
export function checkPortalSession(ctx: AppContext, token: string | undefined): PortalCheck {
  if (!token) return { status: 'none' };
  const s = ctx.db.prepare('SELECT * FROM portal_sessions WHERE id = ?').get(sha256(token)) as PortalSessionRow | undefined;
  if (!s) return { status: 'none' };
  const now = Date.now();
  if (new Date(s.expires_at).getTime() < now || now - sqlDateMs(s.last_activity_at) > PORTAL_IDLE_MINUTES * 60_000) {
    ctx.db.prepare('DELETE FROM portal_sessions WHERE id = ?').run(s.id);
    return { status: 'expired' };
  }
  const link = getMagicLink(ctx, s.magic_link_id);
  if (!link || link.revoked_at) return { status: 'invalid' };
  ctx.db.prepare("UPDATE portal_sessions SET last_activity_at = datetime('now') WHERE id = ?").run(s.id);
  return { status: 'ok', session: s, link };
}
export function destroyPortalSession(ctx: AppContext, sessionId: string) {
  ctx.db.prepare('DELETE FROM portal_sessions WHERE id = ?').run(sessionId);
}

/**
 * Secondary verification for returning clients: last 4 of SSN + date of birth.
 * Attempts are counted on the link; after MAX_VERIFY_ATTEMPTS the link is dead.
 */
export function verifyReturningClient(ctx: AppContext, session: PortalSessionRow, link: MagicLinkRow, last4: string, dob: string, ip?: string): { ok: boolean; locked?: boolean } {
  const client = link.client_id ? getClient(ctx, link.client_id) : undefined;
  const l4 = last4.replace(/\D/g, '');
  let dobNorm: string | null = null;
  try {
    dobNorm = normalizeDate(dob);
  } catch {
    dobNorm = null;
  }
  const ok =
    !!client &&
    !!client.ssn_last4 &&
    !!client.dob &&
    l4.length === 4 &&
    safeEqual(client.ssn_last4, l4) &&
    !!dobNorm &&
    safeEqual(client.dob, dobNorm);
  if (!ok) {
    ctx.db.prepare('UPDATE magic_links SET verify_attempts = verify_attempts + 1 WHERE id = ?').run(link.id);
    const attempts = link.verify_attempts + 1;
    audit(ctx, { actorType: 'client', actorLabel: client?.legal_name ?? 'unknown', actorId: client?.id, action: 'portal.verify_failed', entityType: 'magic_link', entityId: link.id, clientId: link.client_id, details: { attempts }, ip });
    if (attempts >= MAX_VERIFY_ATTEMPTS) {
      ctx.db.prepare('DELETE FROM portal_sessions WHERE magic_link_id = ?').run(link.id);
      return { ok: false, locked: true };
    }
    return { ok: false };
  }
  ctx.db.transaction(() => {
    ctx.db.prepare('UPDATE portal_sessions SET verified = 1 WHERE id = ?').run(session.id);
    ctx.db.prepare("UPDATE magic_links SET verified_at = COALESCE(verified_at, datetime('now')) WHERE id = ?").run(link.id);
  })();
  audit(ctx, { actorType: 'client', actorId: client!.id, actorLabel: client!.legal_name, action: 'portal.verified', entityType: 'magic_link', entityId: link.id, clientId: client!.id, ip });
  return { ok: true };
}

/** Intake identity step: name/email/phone recorded on the session before the full form. */
export function setIntakeIdentity(ctx: AppContext, session: PortalSessionRow, link: MagicLinkRow, identity: { name: string; email: string; phone: string }, ip?: string) {
  ctx.db.transaction(() => {
    ctx.db.prepare('UPDATE portal_sessions SET verified = 1, intake_identity = ? WHERE id = ?').run(JSON.stringify(identity), session.id);
    ctx.db.prepare("UPDATE magic_links SET verified_at = COALESCE(verified_at, datetime('now')) WHERE id = ?").run(link.id);
  })();
  audit(ctx, { actorType: 'client', actorLabel: identity.name, action: 'portal.intake_identity', entityType: 'magic_link', entityId: link.id, details: { email: identity.email, phone: identity.phone }, ip });
}

export function markIntakeCompleted(ctx: AppContext, link: MagicLinkRow, client: ClientRow) {
  ctx.db.prepare("UPDATE magic_links SET completed_at = datetime('now'), created_client_id = ?, client_id = ? WHERE id = ?").run(client.id, client.id, link.id);
}

/** Client activity feed (everything a client did through the portal) for a client record. */
export function clientPortalActivity(ctx: AppContext, clientId: string) {
  return ctx.db.prepare("SELECT * FROM audit_log WHERE client_id = ? AND actor_type = 'client' ORDER BY id DESC LIMIT 200").all(clientId) as any[];
}
