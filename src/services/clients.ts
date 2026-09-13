import type { AppContext } from '../context.js';
import { newId } from '../lib/crypto.js';
import { audit } from './audit.js';
import type { SessionUser } from './permissions.js';
import { can } from './permissions.js';
import { DEFAULT_TAGS } from '../lib/constants.js';

export interface ClientRow {
  id: string;
  legal_name: string;
  preferred_name: string | null;
  ssn_enc: string | null;
  ssn_last4: string | null;
  dob: string | null;
  phone: string | null;
  email: string | null;
  address_line1: string | null;
  address_line2: string | null;
  city: string | null;
  state: string | null;
  zip: string | null;
  filing_status: string | null;
  spouse_name: string | null;
  spouse_ssn_enc: string | null;
  spouse_ssn_last4: string | null;
  spouse_dob: string | null;
  assigned_preparer_id: string | null;
  source: string | null;
  notes: string | null;
  client_since_year: number | null;
  status: string;
  created_by: string | null;
  created_via: string;
  created_at: string;
  updated_at: string;
}
export interface DependentRow {
  id: string;
  client_id: string;
  name: string;
  relationship: string | null;
  dob: string | null;
  ssn_enc: string | null;
  ssn_last4: string | null;
}
export interface YearHistoryRow {
  id: string;
  client_id: string;
  year: number;
  services: string | null;
  fee_cents: number | null;
  notes: string | null;
}

/** Fields a staff member (or import) may set. SSNs arrive as plaintext and are encrypted here. */
export interface ClientInput {
  legal_name: string;
  preferred_name?: string | null;
  ssn?: string | null; // plaintext; undefined = leave unchanged, '' = clear
  dob?: string | null;
  phone?: string | null;
  email?: string | null;
  address_line1?: string | null;
  address_line2?: string | null;
  city?: string | null;
  state?: string | null;
  zip?: string | null;
  filing_status?: string | null;
  spouse_name?: string | null;
  spouse_ssn?: string | null;
  spouse_dob?: string | null;
  assigned_preparer_id?: string | null;
  source?: string | null;
  notes?: string | null;
  client_since_year?: number | null;
  tags?: string[]; // tag names
}

export function normalizeSsn(raw: string | null | undefined): string | null {
  if (raw == null) return null;
  const digits = String(raw).replace(/\D/g, '');
  if (!digits) return null;
  if (digits.length !== 9) throw new Error('SSN must have 9 digits');
  return `${digits.slice(0, 3)}-${digits.slice(3, 5)}-${digits.slice(5)}`;
}
export function maskSsn(last4: string | null, showLast4: boolean): string {
  if (!last4) return '—';
  return showLast4 ? `***-**-${last4}` : '***-**-****';
}
export function normalizeDate(raw: string | null | undefined): string | null {
  if (raw == null || String(raw).trim() === '') return null;
  const s = String(raw).trim();
  let m = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})/);
  if (m) return `${m[1]}-${m[2].padStart(2, '0')}-${m[3].padStart(2, '0')}`;
  m = s.match(/^(\d{1,2})[\/-](\d{1,2})[\/-](\d{2,4})$/);
  if (m) {
    const y = m[3].length === 2 ? (Number(m[3]) > 30 ? '19' + m[3] : '20' + m[3]) : m[3];
    return `${y}-${m[1].padStart(2, '0')}-${m[2].padStart(2, '0')}`;
  }
  const d = new Date(s);
  if (!Number.isNaN(d.getTime())) return d.toISOString().slice(0, 10);
  throw new Error(`Unrecognized date: ${s}`);
}

const clean = (v: unknown): string | null => {
  if (v == null) return null;
  const s = String(v).trim();
  return s === '' ? null : s;
};

export function getClient(ctx: AppContext, id: string): ClientRow | undefined {
  return ctx.db.prepare('SELECT * FROM clients WHERE id = ?').get(id) as ClientRow | undefined;
}

export function listClients(
  ctx: AppContext,
  user: SessionUser,
  opts: { q?: string; tag?: string; preparerId?: string; source?: string } = {},
): (ClientRow & { preparer_name: string | null; tag_names: string | null })[] {
  const where: string[] = [];
  const params: unknown[] = [];
  if (!can.viewAllClients(user)) {
    where.push('c.assigned_preparer_id = ?');
    params.push(user.id);
  }
  if (opts.q) {
    where.push('(c.legal_name LIKE ? OR c.preferred_name LIKE ? OR c.email LIKE ? OR c.phone LIKE ?)');
    const like = `%${opts.q}%`;
    params.push(like, like, like, like);
  }
  if (opts.preparerId) {
    where.push('c.assigned_preparer_id = ?');
    params.push(opts.preparerId);
  }
  if (opts.source) {
    where.push('c.source = ?');
    params.push(opts.source);
  }
  if (opts.tag) {
    where.push('EXISTS (SELECT 1 FROM client_tags ct JOIN tags t ON t.id = ct.tag_id WHERE ct.client_id = c.id AND t.name = ?)');
    params.push(opts.tag);
  }
  const w = where.length ? 'WHERE ' + where.join(' AND ') : '';
  return ctx.db
    .prepare(
      `SELECT c.*, u.name AS preparer_name,
         (SELECT group_concat(t.name, ', ') FROM client_tags ct JOIN tags t ON t.id = ct.tag_id WHERE ct.client_id = c.id) AS tag_names
       FROM clients c LEFT JOIN users u ON u.id = c.assigned_preparer_id ${w}
       ORDER BY c.legal_name LIMIT 500`,
    )
    .all(...params) as any;
}

export function yearsAsClient(c: { client_since_year: number | null; created_at: string }): number {
  const start = c.client_since_year ?? new Date(c.created_at.replace(' ', 'T') + 'Z').getFullYear();
  return Math.max(0, new Date().getFullYear() - start);
}

/** Recompute client_since_year from the earliest year in history (or keep the manually set one if earlier). */
export function recomputeClientSince(ctx: AppContext, clientId: string) {
  const c = getClient(ctx, clientId);
  if (!c) return;
  const row = ctx.db.prepare('SELECT MIN(year) y FROM client_year_history WHERE client_id = ?').get(clientId) as { y: number | null };
  const createdYear = new Date(c.created_at.replace(' ', 'T') + 'Z').getFullYear();
  const candidates = [c.client_since_year, row.y, createdYear].filter((x): x is number => typeof x === 'number' && Number.isFinite(x));
  const min = Math.min(...candidates);
  if (min !== c.client_since_year) ctx.db.prepare('UPDATE clients SET client_since_year = ? WHERE id = ?').run(min, clientId);
}

export interface Actor {
  type: 'user' | 'client' | 'system';
  id?: string | null;
  label: string;
  ip?: string;
  userAgent?: string;
}

export function createClient(ctx: AppContext, input: ClientInput, actor: Actor, createdVia: 'staff' | 'import' | 'portal_intake' = 'staff'): ClientRow {
  const legal = clean(input.legal_name);
  if (!legal) throw new Error('Legal name is required');
  const id = newId();
  const ssn = normalizeSsn(input.ssn);
  const spouseSsn = normalizeSsn(input.spouse_ssn);
  ctx.db.transaction(() => {
    ctx.db
      .prepare(
        `INSERT INTO clients (id, legal_name, preferred_name, ssn_enc, ssn_last4, dob, phone, email, address_line1, address_line2, city, state, zip,
          filing_status, spouse_name, spouse_ssn_enc, spouse_ssn_last4, spouse_dob, assigned_preparer_id, source, notes, client_since_year, created_by, created_via)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        legal,
        clean(input.preferred_name),
        ssn ? ctx.cipher.encrypt(ssn, `client_ssn:${id}`) : null,
        ssn ? ssn.slice(-4) : null,
        normalizeDate(input.dob),
        clean(input.phone),
        clean(input.email),
        clean(input.address_line1),
        clean(input.address_line2),
        clean(input.city),
        clean(input.state),
        clean(input.zip),
        clean(input.filing_status),
        clean(input.spouse_name),
        spouseSsn ? ctx.cipher.encrypt(spouseSsn, `spouse_ssn:${id}`) : null,
        spouseSsn ? spouseSsn.slice(-4) : null,
        normalizeDate(input.spouse_dob),
        clean(input.assigned_preparer_id),
        clean(input.source),
        clean(input.notes),
        input.client_since_year ?? null,
        actor.type === 'user' ? actor.id ?? null : null,
        createdVia,
      );
    if (input.tags) setClientTags(ctx, id, input.tags);
    recomputeClientSince(ctx, id);
  })();
  audit(ctx, {
    actorType: actor.type,
    actorId: actor.id,
    actorLabel: actor.label,
    action: 'client.create',
    entityType: 'client',
    entityId: id,
    clientId: id,
    details: { legal_name: legal, via: createdVia },
    ip: actor.ip,
    userAgent: actor.userAgent,
  });
  return getClient(ctx, id)!;
}

/** Updates the given fields; records which fields changed (never the SSN value itself) in the audit log. */
export function updateClient(ctx: AppContext, id: string, input: Partial<ClientInput>, actor: Actor): ClientRow {
  const before = getClient(ctx, id);
  if (!before) throw new Error('Client not found');
  const sets: string[] = [];
  const params: unknown[] = [];
  const changed: Record<string, { from: unknown; to: unknown }> = {};
  const plain: (keyof ClientInput & keyof ClientRow)[] = [
    'legal_name', 'preferred_name', 'dob', 'phone', 'email', 'address_line1', 'address_line2', 'city', 'state', 'zip',
    'filing_status', 'spouse_name', 'spouse_dob', 'assigned_preparer_id', 'source', 'notes',
  ];
  for (const f of plain) {
    if (!(f in input)) continue;
    let v = clean(input[f]);
    if (f === 'dob' || f === 'spouse_dob') v = normalizeDate(v);
    if (f === 'legal_name' && !v) throw new Error('Legal name is required');
    if (v !== before[f]) {
      sets.push(`${f} = ?`);
      params.push(v);
      changed[f] = { from: before[f], to: v };
    }
  }
  if ('client_since_year' in input && input.client_since_year !== before.client_since_year) {
    sets.push('client_since_year = ?');
    params.push(input.client_since_year ?? null);
    changed.client_since_year = { from: before.client_since_year, to: input.client_since_year ?? null };
  }
  if (input.ssn !== undefined) {
    const ssn = normalizeSsn(input.ssn);
    const last4 = ssn ? ssn.slice(-4) : null;
    if (last4 !== before.ssn_last4 || (ssn && before.ssn_enc && ctx.cipher.decrypt(before.ssn_enc, `client_ssn:${id}`) !== ssn)) {
      sets.push('ssn_enc = ?', 'ssn_last4 = ?');
      params.push(ssn ? ctx.cipher.encrypt(ssn, `client_ssn:${id}`) : null, last4);
      changed.ssn = { from: before.ssn_last4 ? `***-**-${before.ssn_last4}` : null, to: last4 ? `***-**-${last4}` : null };
    }
  }
  if (input.spouse_ssn !== undefined) {
    const ssn = normalizeSsn(input.spouse_ssn);
    const last4 = ssn ? ssn.slice(-4) : null;
    if (last4 !== before.spouse_ssn_last4 || (ssn && before.spouse_ssn_enc && ctx.cipher.decrypt(before.spouse_ssn_enc, `spouse_ssn:${id}`) !== ssn)) {
      sets.push('spouse_ssn_enc = ?', 'spouse_ssn_last4 = ?');
      params.push(ssn ? ctx.cipher.encrypt(ssn, `spouse_ssn:${id}`) : null, last4);
      changed.spouse_ssn = { from: before.spouse_ssn_last4 ? `***-**-${before.spouse_ssn_last4}` : null, to: last4 ? `***-**-${last4}` : null };
    }
  }
  ctx.db.transaction(() => {
    if (sets.length) {
      sets.push("updated_at = datetime('now')");
      ctx.db.prepare(`UPDATE clients SET ${sets.join(', ')} WHERE id = ?`).run(...params, id);
    }
    if (input.tags) {
      const beforeTags = getClientTags(ctx, id).map((t) => t.name).sort();
      const afterTags = [...new Set(input.tags.map((t) => t.trim()).filter(Boolean))].sort();
      if (JSON.stringify(beforeTags) !== JSON.stringify(afterTags)) {
        setClientTags(ctx, id, afterTags);
        changed.tags = { from: beforeTags, to: afterTags };
      }
    }
    recomputeClientSince(ctx, id);
  })();
  if (Object.keys(changed).length) {
    audit(ctx, {
      actorType: actor.type,
      actorId: actor.id,
      actorLabel: actor.label,
      action: 'client.update',
      entityType: 'client',
      entityId: id,
      clientId: id,
      details: { changed },
      ip: actor.ip,
      userAgent: actor.userAgent,
    });
  }
  return getClient(ctx, id)!;
}

export function deleteClient(ctx: AppContext, id: string, actor: Actor) {
  const c = getClient(ctx, id);
  if (!c) return;
  ctx.db.prepare('DELETE FROM clients WHERE id = ?').run(id);
  audit(ctx, { actorType: actor.type, actorId: actor.id, actorLabel: actor.label, action: 'client.delete', entityType: 'client', entityId: id, clientId: id, details: { legal_name: c.legal_name }, ip: actor.ip });
}

/** Decrypts the full SSN. Always audited — this is the one place full SSNs leave the database. */
export function revealSsn(ctx: AppContext, client: ClientRow, actor: Actor, which: 'client' | 'spouse' = 'client'): string | null {
  const enc = which === 'spouse' ? client.spouse_ssn_enc : client.ssn_enc;
  audit(ctx, {
    actorType: actor.type,
    actorId: actor.id,
    actorLabel: actor.label,
    action: 'client.ssn_reveal',
    entityType: 'client',
    entityId: client.id,
    clientId: client.id,
    details: { which },
    ip: actor.ip,
    userAgent: actor.userAgent,
  });
  if (!enc) return null;
  return ctx.cipher.decrypt(enc, `${which === 'spouse' ? 'spouse_ssn' : 'client_ssn'}:${client.id}`);
}

// ---------- Tags ----------
export function ensureDefaultTags(ctx: AppContext) {
  const ins = ctx.db.prepare('INSERT OR IGNORE INTO tags (id, name) VALUES (?, ?)');
  for (const t of DEFAULT_TAGS) ins.run(newId(), t);
}
export function listTags(ctx: AppContext): { id: string; name: string }[] {
  return ctx.db.prepare('SELECT * FROM tags ORDER BY name').all() as any;
}
export function getClientTags(ctx: AppContext, clientId: string): { id: string; name: string }[] {
  return ctx.db.prepare('SELECT t.* FROM tags t JOIN client_tags ct ON ct.tag_id = t.id WHERE ct.client_id = ? ORDER BY t.name').all(clientId) as any;
}
export function setClientTags(ctx: AppContext, clientId: string, names: string[]) {
  ctx.db.prepare('DELETE FROM client_tags WHERE client_id = ?').run(clientId);
  for (const raw of names) {
    const name = raw.trim();
    if (!name) continue;
    let tag = ctx.db.prepare('SELECT id FROM tags WHERE name = ?').get(name) as { id: string } | undefined;
    if (!tag) {
      tag = { id: newId() };
      ctx.db.prepare('INSERT INTO tags (id, name) VALUES (?, ?)').run(tag.id, name);
    }
    ctx.db.prepare('INSERT OR IGNORE INTO client_tags (client_id, tag_id) VALUES (?, ?)').run(clientId, tag.id);
  }
}
export function createTag(ctx: AppContext, name: string) {
  ctx.db.prepare('INSERT OR IGNORE INTO tags (id, name) VALUES (?, ?)').run(newId(), name.trim());
}

// ---------- Dependents ----------
export function listDependents(ctx: AppContext, clientId: string): DependentRow[] {
  return ctx.db.prepare('SELECT * FROM dependents WHERE client_id = ? ORDER BY created_at').all(clientId) as DependentRow[];
}
export function addDependent(ctx: AppContext, clientId: string, d: { name: string; relationship?: string | null; dob?: string | null; ssn?: string | null }, actor: Actor): DependentRow {
  const name = clean(d.name);
  if (!name) throw new Error('Dependent name is required');
  const id = newId();
  const ssn = normalizeSsn(d.ssn);
  ctx.db
    .prepare('INSERT INTO dependents (id, client_id, name, relationship, dob, ssn_enc, ssn_last4) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, clientId, name, clean(d.relationship), normalizeDate(d.dob), ssn ? ctx.cipher.encrypt(ssn, `dependent_ssn:${id}`) : null, ssn ? ssn.slice(-4) : null);
  audit(ctx, { actorType: actor.type, actorId: actor.id, actorLabel: actor.label, action: 'client.dependent_add', entityType: 'dependent', entityId: id, clientId, details: { name, relationship: d.relationship }, ip: actor.ip });
  return ctx.db.prepare('SELECT * FROM dependents WHERE id = ?').get(id) as DependentRow;
}
export function updateDependent(ctx: AppContext, dep: DependentRow, d: { name?: string; relationship?: string | null; dob?: string | null; ssn?: string | null }, actor: Actor) {
  const name = clean(d.name) ?? dep.name;
  const ssn = d.ssn === undefined ? undefined : normalizeSsn(d.ssn);
  ctx.db
    .prepare('UPDATE dependents SET name = ?, relationship = ?, dob = ?, ssn_enc = ?, ssn_last4 = ? WHERE id = ?')
    .run(
      name,
      d.relationship === undefined ? dep.relationship : clean(d.relationship),
      d.dob === undefined ? dep.dob : normalizeDate(d.dob),
      ssn === undefined ? dep.ssn_enc : ssn ? ctx.cipher.encrypt(ssn, `dependent_ssn:${dep.id}`) : null,
      ssn === undefined ? dep.ssn_last4 : ssn ? ssn.slice(-4) : null,
      dep.id,
    );
  audit(ctx, { actorType: actor.type, actorId: actor.id, actorLabel: actor.label, action: 'client.dependent_update', entityType: 'dependent', entityId: dep.id, clientId: dep.client_id, details: { name }, ip: actor.ip });
}
export function deleteDependent(ctx: AppContext, dep: DependentRow, actor: Actor) {
  ctx.db.prepare('DELETE FROM dependents WHERE id = ?').run(dep.id);
  audit(ctx, { actorType: actor.type, actorId: actor.id, actorLabel: actor.label, action: 'client.dependent_delete', entityType: 'dependent', entityId: dep.id, clientId: dep.client_id, details: { name: dep.name }, ip: actor.ip });
}

// ---------- Year history ----------
export function listYearHistory(ctx: AppContext, clientId: string): YearHistoryRow[] {
  return ctx.db.prepare('SELECT * FROM client_year_history WHERE client_id = ? ORDER BY year DESC').all(clientId) as YearHistoryRow[];
}
export function upsertYearHistory(ctx: AppContext, clientId: string, h: { year: number; services?: string | null; fee_cents?: number | null; notes?: string | null }, actor: Actor) {
  if (!Number.isInteger(h.year) || h.year < 1950 || h.year > 2100) throw new Error('Invalid year');
  ctx.db
    .prepare(
      `INSERT INTO client_year_history (id, client_id, year, services, fee_cents, notes) VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(client_id, year) DO UPDATE SET services = excluded.services, fee_cents = excluded.fee_cents, notes = excluded.notes`,
    )
    .run(newId(), clientId, h.year, clean(h.services), h.fee_cents ?? null, clean(h.notes));
  recomputeClientSince(ctx, clientId);
  audit(ctx, { actorType: actor.type, actorId: actor.id, actorLabel: actor.label, action: 'client.history_upsert', entityType: 'client', entityId: clientId, clientId, details: { year: h.year, services: h.services, fee_cents: h.fee_cents }, ip: actor.ip });
}
export function deleteYearHistory(ctx: AppContext, clientId: string, year: number, actor: Actor) {
  ctx.db.prepare('DELETE FROM client_year_history WHERE client_id = ? AND year = ?').run(clientId, year);
  audit(ctx, { actorType: actor.type, actorId: actor.id, actorLabel: actor.label, action: 'client.history_delete', entityType: 'client', entityId: clientId, clientId, details: { year }, ip: actor.ip });
}
