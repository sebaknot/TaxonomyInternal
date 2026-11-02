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
  verified: boolean;
  intake_identity: string | null;
  created_at: string;
  last_activity_at: string;
  expires_at: string;
  ip: string | null;
}

const MAX_VERIFY_ATTEMPTS = 5;
const PORTAL_IDLE_MINUTES = 30;
const PORTAL_ABSOLUTE_HOURS = 4;

export async function createMagicLink(
  ctx: AppContext,
  input: { type: 'returning' | 'intake'; clientId?: string | null; taxYear: number; label?: string | null },
  actor: SessionUser,
  ip?: string,
): Promise<{ link: MagicLinkRow; url: string }> {
  if (input.type === 'returning' && !input.clientId) throw new Error('Returning-client links require a client');
  const token = randomToken(32);
  const hours = await getSettingInt(ctx, SETTING_KEYS.magicLinkHours);
  const id = newId();
  const expires = new Date(Date.now() + hours * 3600_000).toISOString();
  await ctx.db.run(
    'INSERT INTO magic_links (id, token_hash, type, client_id, tax_year, label, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    id,
    sha256(token),
    input.type,
    input.clientId ?? null,
    input.taxYear,
    input.label ?? null,
    actor.id,
    expires,
  );
  await audit(ctx, {
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
  return { link: (await getMagicLink(ctx, id))!, url };
}

export function getMagicLink(ctx: AppContext, id: string) {
  return ctx.db.one<MagicLinkRow>('SELECT * FROM magic_links WHERE id = ?', id);
}
export function findMagicLinkByToken(ctx: AppContext, token: string) {
  return ctx.db.one<MagicLinkRow>('SELECT * FROM magic_links WHERE token_hash = ?', sha256(token));
}
export function listMagicLinksForClient(ctx: AppContext, clientId: string) {
  return ctx.db.all<MagicLinkRow & { creator: string }>('SELECT m.*, u.name creator FROM magic_links m JOIN users u ON u.id = m.created_by WHERE m.client_id = ? ORDER BY m.created_at DESC', clientId);
}
export function listIntakeLinks(ctx: AppContext) {
  return ctx.db.all<MagicLinkRow & { creator: string; created_client_name: string | null }>(
    `SELECT m.*, u.name creator, c.legal_name created_client_name FROM magic_links m JOIN users u ON u.id = m.created_by
     LEFT JOIN clients c ON c.id = m.created_client_id WHERE m.type = 'intake' ORDER BY m.created_at DESC LIMIT 200`,
  );
}
export async function revokeMagicLink(ctx: AppContext, link: MagicLinkRow, actor: SessionUser, ip?: string) {
  await ctx.db.tx(async (t) => {
    await t.run('UPDATE magic_links SET revoked_at = now() WHERE id = ?', link.id);
    await t.run('DELETE FROM portal_sessions WHERE magic_link_id = ?', link.id);
  });
  await audit(ctx, { actorType: 'user', actorId: actor.id, actorLabel: actor.email, action: 'magic_link.revoke', entityType: 'magic_link', entityId: link.id, clientId: link.client_id, ip });
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

export async function createPortalSession(ctx: AppContext, link: MagicLinkRow, ip?: string): Promise<string> {
  const token = randomToken(32);
  const expires = new Date(Math.min(Date.now() + PORTAL_ABSOLUTE_HOURS * 3600_000, new Date(link.expires_at).getTime() + PORTAL_ABSOLUTE_HOURS * 3600_000)).toISOString();
  await ctx.db.run(
    'INSERT INTO portal_sessions (id, magic_link_id, client_id, csrf_token, verified, expires_at, ip) VALUES (?, ?, ?, ?, false, ?, ?)',
    sha256(token),
    link.id,
    link.client_id,
    randomToken(24),
    expires,
    ip ?? null,
  );
  return token;
}

export type PortalCheck = { status: 'ok'; session: PortalSessionRow; link: MagicLinkRow } | { status: 'none' | 'expired' | 'invalid' };
export async function checkPortalSession(ctx: AppContext, token: string | undefined): Promise<PortalCheck> {
  if (!token) return { status: 'none' };
  const s = await ctx.db.one<PortalSessionRow>('SELECT * FROM portal_sessions WHERE id = ?', sha256(token));
  if (!s) return { status: 'none' };
  const now = Date.now();
  if (new Date(s.expires_at).getTime() < now || now - sqlDateMs(s.last_activity_at) > PORTAL_IDLE_MINUTES * 60_000) {
    await ctx.db.run('DELETE FROM portal_sessions WHERE id = ?', s.id);
    return { status: 'expired' };
  }
  const link = await getMagicLink(ctx, s.magic_link_id);
  if (!link || link.revoked_at) return { status: 'invalid' };
  await ctx.db.run('UPDATE portal_sessions SET last_activity_at = now() WHERE id = ?', s.id);
  return { status: 'ok', session: s, link };
}
export async function destroyPortalSession(ctx: AppContext, sessionId: string) {
  await ctx.db.run('DELETE FROM portal_sessions WHERE id = ?', sessionId);
}

/**
 * Secondary verification for returning clients: last 4 of SSN + date of birth.
 * Attempts are counted on the link; after MAX_VERIFY_ATTEMPTS the link is dead.
 */
export async function verifyReturningClient(ctx: AppContext, session: PortalSessionRow, link: MagicLinkRow, last4: string, dob: string, ip?: string): Promise<{ ok: boolean; locked?: boolean }> {
  const client = link.client_id ? await getClient(ctx, link.client_id) : undefined;
  const l4 = last4.replace(/\D/g, '');
  let dobNorm: string | null = null;
  try {
    dobNorm = normalizeDate(dob);
  } catch {
    dobNorm = null;
  }
  const ok = !!client && !!client.ssn_last4 && !!client.dob && l4.length === 4 && safeEqual(client.ssn_last4, l4) && !!dobNorm && safeEqual(client.dob, dobNorm);
  if (!ok) {
    const row = await ctx.db.one<{ verify_attempts: number }>('UPDATE magic_links SET verify_attempts = verify_attempts + 1 WHERE id = ? RETURNING verify_attempts', link.id);
    const attempts = row?.verify_attempts ?? link.verify_attempts + 1;
    await audit(ctx, { actorType: 'client', actorLabel: client?.legal_name ?? 'unknown', actorId: client?.id, action: 'portal.verify_failed', entityType: 'magic_link', entityId: link.id, clientId: link.client_id, details: { attempts }, ip });
    if (attempts >= MAX_VERIFY_ATTEMPTS) {
      await ctx.db.run('DELETE FROM portal_sessions WHERE magic_link_id = ?', link.id);
      return { ok: false, locked: true };
    }
    return { ok: false };
  }
  await ctx.db.tx(async (t) => {
    await t.run('UPDATE portal_sessions SET verified = true WHERE id = ?', session.id);
    await t.run('UPDATE magic_links SET verified_at = COALESCE(verified_at, now()) WHERE id = ?', link.id);
  });
  await audit(ctx, { actorType: 'client', actorId: client!.id, actorLabel: client!.legal_name, action: 'portal.verified', entityType: 'magic_link', entityId: link.id, clientId: client!.id, ip });
  return { ok: true };
}

/** Intake identity step: name/email/phone recorded on the session before the full form. */
export async function setIntakeIdentity(ctx: AppContext, session: PortalSessionRow, link: MagicLinkRow, identity: { name: string; email: string; phone: string }, ip?: string) {
  await ctx.db.tx(async (t) => {
    await t.run('UPDATE portal_sessions SET verified = true, intake_identity = ? WHERE id = ?', JSON.stringify(identity), session.id);
    await t.run('UPDATE magic_links SET verified_at = COALESCE(verified_at, now()) WHERE id = ?', link.id);
  });
  await audit(ctx, { actorType: 'client', actorLabel: identity.name, action: 'portal.intake_identity', entityType: 'magic_link', entityId: link.id, details: { email: identity.email, phone: identity.phone }, ip });
}

export async function markIntakeCompleted(ctx: AppContext, link: MagicLinkRow, client: ClientRow) {
  await ctx.db.run('UPDATE magic_links SET completed_at = now(), created_client_id = ?, client_id = ? WHERE id = ?', client.id, client.id, link.id);
}

/** Client activity feed (everything a client did through the portal) for a client record. */
export function clientPortalActivity(ctx: AppContext, clientId: string) {
  return ctx.db.all<any>("SELECT * FROM audit_log WHERE client_id = ? AND actor_type = 'client' ORDER BY id DESC LIMIT 200", clientId);
}
