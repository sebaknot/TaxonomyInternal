import type { AppContext } from '../context.js';

export interface AuditEntry {
  actorType: 'user' | 'client' | 'system' | 'anonymous';
  actorId?: string | null;
  actorLabel?: string | null;
  action: string;
  entityType?: string | null;
  entityId?: string | null;
  clientId?: string | null;
  details?: Record<string, unknown> | null;
  ip?: string | null;
  userAgent?: string | null;
}

export async function audit(ctx: AppContext, e: AuditEntry): Promise<void> {
  await ctx.db.run(
    `INSERT INTO audit_log (actor_type, actor_id, actor_label, action, entity_type, entity_id, client_id, details, ip, user_agent)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    e.actorType,
    e.actorId ?? null,
    e.actorLabel ?? null,
    e.action,
    e.entityType ?? null,
    e.entityId ?? null,
    e.clientId ?? null,
    e.details ? JSON.stringify(e.details) : null,
    e.ip ?? null,
    e.userAgent ? String(e.userAgent).slice(0, 500) : null,
  );
}

export interface AuditRow {
  id: number;
  ts: string;
  actor_type: string;
  actor_id: string | null;
  actor_label: string | null;
  action: string;
  entity_type: string | null;
  entity_id: string | null;
  client_id: string | null;
  details: string | null;
  ip: string | null;
  user_agent: string | null;
}

export async function listAudit(
  ctx: AppContext,
  opts: { clientId?: string; actionPrefix?: string; actorId?: string; limit?: number; offset?: number } = {},
): Promise<{ rows: AuditRow[]; total: number }> {
  const where: string[] = [];
  const params: unknown[] = [];
  if (opts.clientId) {
    where.push('client_id = ?');
    params.push(opts.clientId);
  }
  if (opts.actionPrefix) {
    where.push('action LIKE ?');
    params.push(opts.actionPrefix + '%');
  }
  if (opts.actorId) {
    where.push('actor_id = ?');
    params.push(opts.actorId);
  }
  const w = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const total = await ctx.db.scalar<number>(`SELECT COUNT(*) FROM audit_log ${w}`, ...params);
  const rows = await ctx.db.all<AuditRow>(`SELECT * FROM audit_log ${w} ORDER BY id DESC LIMIT ? OFFSET ?`, ...params, opts.limit ?? 100, opts.offset ?? 0);
  return { rows, total };
}
