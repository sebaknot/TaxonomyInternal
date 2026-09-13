import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { HttpError, requireRole } from '../middleware/index.js';
import { can, canAccessClient } from '../services/permissions.js';
import * as C from '../services/clients.js';
import { listActiveUsersByRole } from '../services/auth.js';
import { listAudit, audit } from '../services/audit.js';
import { clientVault } from '../services/documents.js';
import { createMagicLink, listMagicLinksForClient, getMagicLink, revokeMagicLink, listIntakeLinks, linkState, clientPortalActivity } from '../services/magic.js';
import { getSettingInt } from '../services/settings.js';
import { SETTING_KEYS } from '../lib/constants.js';

const optStr = z.string().max(2000).optional().transform((v) => (v == null ? null : v));

const clientSchema = z.object({
  legal_name: z.string().trim().min(1, 'Legal name is required').max(200),
  preferred_name: optStr,
  ssn: z.string().max(20).optional(),
  dob: optStr,
  phone: optStr,
  email: z.string().trim().max(200).optional().transform((v) => (v ? v : null)),
  address_line1: optStr,
  address_line2: optStr,
  city: optStr,
  state: optStr,
  zip: optStr,
  filing_status: optStr,
  spouse_name: optStr,
  spouse_ssn: z.string().max(20).optional(),
  spouse_dob: optStr,
  assigned_preparer_id: optStr,
  source: optStr,
  notes: z.string().max(20000).optional(),
  client_since_year: z.string().optional(),
  tags: z.union([z.string(), z.array(z.string())]).optional(),
});

function actorOf(req: Request): C.Actor {
  return { type: 'user', id: req.user!.id, label: req.user!.email, ip: req.meta.ip, userAgent: req.meta.userAgent };
}

/** Loads the client into res.locals.client, hiding its existence from users without access. */
function loadClient(req: Request, res: Response, next: NextFunction) {
  const client = C.getClient(req.ctx, String(req.params.id));
  if (!client || !canAccessClient(req.user!, client)) return next(new HttpError(404, 'Client not found.'));
  res.locals.client = client;
  next();
}

function parseClientBody(req: Request, forCreate: boolean): Partial<C.ClientInput> {
  const parsed = clientSchema.safeParse(req.body);
  if (!parsed.success) throw new HttpError(400, parsed.error.issues.map((i) => i.message).join('; '));
  const d = parsed.data;
  const u = req.user!;
  const out: Partial<C.ClientInput> = {
    legal_name: d.legal_name,
    preferred_name: d.preferred_name,
    dob: d.dob,
    phone: d.phone,
    email: d.email,
    address_line1: d.address_line1,
    address_line2: d.address_line2,
    city: d.city,
    state: d.state,
    zip: d.zip,
    filing_status: d.filing_status,
    spouse_name: d.spouse_name,
    spouse_dob: d.spouse_dob,
    source: d.source,
  };
  // Blank SSN inputs mean "leave unchanged"; an explicit "clear" checkbox removes it.
  if (d.ssn && d.ssn.trim()) out.ssn = d.ssn;
  else if (req.body.clear_ssn === '1') out.ssn = '';
  if (d.spouse_ssn && d.spouse_ssn.trim()) out.spouse_ssn = d.spouse_ssn;
  else if (req.body.clear_spouse_ssn === '1') out.spouse_ssn = '';
  if (can.seeSensitiveFields(u)) {
    out.notes = d.notes ?? null;
    out.client_since_year = d.client_since_year && d.client_since_year.trim() ? parseInt(d.client_since_year, 10) : null;
  }
  if (can.assignPreparer(u)) out.assigned_preparer_id = d.assigned_preparer_id || null;
  else if (forCreate) out.assigned_preparer_id = u.role === 'preparer' ? u.id : null;
  if (d.tags !== undefined) out.tags = (Array.isArray(d.tags) ? d.tags : d.tags.split(',')).map((t) => t.trim()).filter(Boolean);
  else if (!forCreate) out.tags = [];
  return out;
}

export function clientsRouter() {
  const r = Router();
  r.use(requireRole(can.accessClients));

  r.get('/', (req, res) => {
    const q = String(req.query.q || '').trim();
    const tag = String(req.query.tag || '');
    const preparerId = String(req.query.preparer || '');
    const source = String(req.query.source || '');
    const clients = C.listClients(req.ctx, req.user!, { q, tag, preparerId, source });
    res.render('clients/index', {
      title: 'Clients',
      clients,
      q,
      tag,
      preparerId,
      source,
      tags: C.listTags(req.ctx),
      preparers: listActiveUsersByRole(req.ctx, ['preparer', 'manager', 'admin']),
      yearsAsClient: C.yearsAsClient,
      maskSsn: (last4: string | null) => C.maskSsn(last4, can.seeSsnLast4(req.user!)),
    });
  });

  // ----- Intake (new-client) magic links -----
  r.get('/intake-links', requireRole(can.generateMagicLinks), (req, res) => {
    res.render('clients/intake_links', { title: 'New-client intake links', links: listIntakeLinks(req.ctx), linkState, taxYear: getSettingInt(req.ctx, SETTING_KEYS.currentTaxYear), created: null });
  });
  r.post('/intake-links', requireRole(can.generateMagicLinks), (req, res) => {
    const taxYear = parseInt(String(req.body.tax_year), 10);
    const label = String(req.body.label || '').trim().slice(0, 200) || null;
    if (!Number.isInteger(taxYear)) throw new HttpError(400, 'Tax year is required');
    const created = createMagicLink(req.ctx, { type: 'intake', taxYear, label }, req.user!, req.meta.ip);
    res.render('clients/intake_links', { title: 'New-client intake links', links: listIntakeLinks(req.ctx), linkState, taxYear, created });
  });
  r.post('/intake-links/:linkId/revoke', requireRole(can.generateMagicLinks), (req, res) => {
    const link = getMagicLink(req.ctx, String(req.params.linkId));
    if (!link || link.type !== 'intake') throw new HttpError(404, 'Link not found');
    revokeMagicLink(req.ctx, link, req.user!, req.meta.ip);
    req.flash('success', 'Intake link revoked.');
    res.redirect('/clients/intake-links');
  });

  r.get('/new', requireRole(can.createClients), (req, res) => {
    res.render('clients/form', { title: 'New client', client: null, clientTags: [], tags: C.listTags(req.ctx), preparers: listActiveUsersByRole(req.ctx, ['preparer', 'manager', 'admin']), can, error: null });
  });
  r.post('/', requireRole(can.createClients), (req, res) => {
    try {
      const input = parseClientBody(req, true) as C.ClientInput;
      const client = C.createClient(req.ctx, input, actorOf(req), 'staff');
      req.flash('success', 'Client created.');
      res.redirect(`/clients/${client.id}`);
    } catch (err) {
      res.status(400).render('clients/form', { title: 'New client', client: null, clientTags: [], tags: C.listTags(req.ctx), preparers: listActiveUsersByRole(req.ctx, ['preparer', 'manager', 'admin']), can, error: (err as Error).message, form: req.body });
    }
  });

  r.get('/:id', loadClient, (req, res) => {
    const client = res.locals.client as C.ClientRow;
    const u = req.user!;
    const sensitive = can.seeSensitiveFields(u);
    res.render('clients/show', {
      title: client.legal_name,
      client,
      can,
      sensitive,
      maskSsn: (last4: string | null) => C.maskSsn(last4, can.seeSsnLast4(u)),
      years: C.yearsAsClient(client),
      clientTags: C.getClientTags(req.ctx, client.id),
      dependents: C.listDependents(req.ctx, client.id),
      history: sensitive ? C.listYearHistory(req.ctx, client.id) : [],
      preparer: client.assigned_preparer_id ? req.ctx.db.prepare('SELECT name FROM users WHERE id = ?').get(client.assigned_preparer_id) : null,
      vault: clientVault(req.ctx, client.id),
      magicLinks: can.generateMagicLinks(u) ? listMagicLinksForClient(req.ctx, client.id) : [],
      linkState,
      activity: clientPortalActivity(req.ctx, client.id),
      recentAudit: listAudit(req.ctx, { clientId: client.id, limit: 25 }).rows,
      taxYear: getSettingInt(req.ctx, SETTING_KEYS.currentTaxYear),
      createdLink: null,
    });
  });

  r.get('/:id/edit', loadClient, requireRole(can.editClientCore), (req, res) => {
    const client = res.locals.client as C.ClientRow;
    res.render('clients/form', { title: `Edit ${client.legal_name}`, client, clientTags: C.getClientTags(req.ctx, client.id).map((t) => t.name), tags: C.listTags(req.ctx), preparers: listActiveUsersByRole(req.ctx, ['preparer', 'manager', 'admin']), can, error: null });
  });
  r.post('/:id', loadClient, requireRole(can.editClientCore), (req, res) => {
    const client = res.locals.client as C.ClientRow;
    try {
      C.updateClient(req.ctx, client.id, parseClientBody(req, false), actorOf(req));
      req.flash('success', 'Client updated.');
      res.redirect(`/clients/${client.id}`);
    } catch (err) {
      res.status(400).render('clients/form', { title: `Edit ${client.legal_name}`, client, clientTags: C.getClientTags(req.ctx, client.id).map((t) => t.name), tags: C.listTags(req.ctx), preparers: listActiveUsersByRole(req.ctx, ['preparer', 'manager', 'admin']), can, error: (err as Error).message, form: req.body });
    }
  });
  r.post('/:id/delete', loadClient, requireRole(can.deleteClients), (req, res) => {
    C.deleteClient(req.ctx, res.locals.client.id, actorOf(req));
    req.flash('success', 'Client deleted.');
    res.redirect('/clients');
  });

  /** Explicit, audited reveal of the full SSN. Admin only. Returns JSON for the in-page button. */
  r.post('/:id/ssn/reveal', loadClient, requireRole(can.revealSsn), (req, res) => {
    const which = req.body.which === 'spouse' ? 'spouse' : req.body.which === 'dependent' ? 'dependent' : 'client';
    if (which === 'dependent') {
      const dep = req.ctx.db.prepare('SELECT * FROM dependents WHERE id = ? AND client_id = ?').get(String(req.body.dependent_id), res.locals.client.id) as C.DependentRow | undefined;
      if (!dep) throw new HttpError(404, 'Dependent not found');
      const ssn = dep.ssn_enc ? req.ctx.cipher.decrypt(dep.ssn_enc, `dependent_ssn:${dep.id}`) : null;
      audit(req.ctx, { actorType: 'user', actorId: req.user!.id, actorLabel: req.user!.email, action: 'client.ssn_reveal', entityType: 'dependent', entityId: dep.id, clientId: dep.client_id, details: { which: 'dependent', name: dep.name }, ip: req.meta.ip, userAgent: req.meta.userAgent });
      return res.json({ ssn });
    }
    const ssn = C.revealSsn(req.ctx, res.locals.client, actorOf(req), which);
    res.json({ ssn });
  });

  // ----- Dependents -----
  r.post('/:id/dependents', loadClient, requireRole(can.editClientCore), (req, res) => {
    try {
      C.addDependent(req.ctx, res.locals.client.id, { name: String(req.body.name || ''), relationship: req.body.relationship, dob: req.body.dob, ssn: req.body.ssn }, actorOf(req));
      req.flash('success', 'Dependent added.');
    } catch (err) {
      req.flash('error', (err as Error).message);
    }
    res.redirect(`/clients/${res.locals.client.id}#dependents`);
  });
  r.post('/:id/dependents/:depId', loadClient, requireRole(can.editClientCore), (req, res) => {
    const dep = req.ctx.db.prepare('SELECT * FROM dependents WHERE id = ? AND client_id = ?').get(String(req.params.depId), res.locals.client.id) as C.DependentRow | undefined;
    if (!dep) throw new HttpError(404, 'Dependent not found');
    try {
      if (req.body._action === 'delete') C.deleteDependent(req.ctx, dep, actorOf(req));
      else C.updateDependent(req.ctx, dep, { name: req.body.name, relationship: req.body.relationship, dob: req.body.dob, ssn: req.body.ssn && String(req.body.ssn).trim() ? req.body.ssn : undefined }, actorOf(req));
      req.flash('success', 'Dependent saved.');
    } catch (err) {
      req.flash('error', (err as Error).message);
    }
    res.redirect(`/clients/${res.locals.client.id}#dependents`);
  });

  // ----- Year history -----
  r.post('/:id/history', loadClient, requireRole(can.editClientSensitive), (req, res) => {
    try {
      const year = parseInt(String(req.body.year), 10);
      const fee = String(req.body.fee || '').replace(/[^0-9.]/g, '');
      if (req.body._action === 'delete') C.deleteYearHistory(req.ctx, res.locals.client.id, year, actorOf(req));
      else C.upsertYearHistory(req.ctx, res.locals.client.id, { year, services: req.body.services, fee_cents: fee ? Math.round(parseFloat(fee) * 100) : null, notes: req.body.notes }, actorOf(req));
      req.flash('success', 'History saved.');
    } catch (err) {
      req.flash('error', (err as Error).message);
    }
    res.redirect(`/clients/${res.locals.client.id}#history`);
  });

  // ----- Returning-client magic links -----
  r.post('/:id/magic-links', loadClient, requireRole(can.generateMagicLinks), (req, res) => {
    const taxYear = parseInt(String(req.body.tax_year), 10);
    if (!Number.isInteger(taxYear)) throw new HttpError(400, 'Tax year is required');
    const client = res.locals.client as C.ClientRow;
    if (!client.ssn_last4 || !client.dob) {
      req.flash('error', 'This client needs an SSN and date of birth on file before a returning-client link can be verified. Add them first.');
      return res.redirect(`/clients/${client.id}#portal`);
    }
    const created = createMagicLink(req.ctx, { type: 'returning', clientId: client.id, taxYear }, req.user!, req.meta.ip);
    res.render('clients/link_created', { title: 'Magic link created', client, created, sendTo: client.email });
  });
  r.post('/:id/magic-links/:linkId/revoke', loadClient, requireRole(can.generateMagicLinks), (req, res) => {
    const link = getMagicLink(req.ctx, String(req.params.linkId));
    if (!link || link.client_id !== res.locals.client.id) throw new HttpError(404, 'Link not found');
    revokeMagicLink(req.ctx, link, req.user!, req.meta.ip);
    req.flash('success', 'Link revoked.');
    res.redirect(`/clients/${res.locals.client.id}#portal`);
  });
  r.post('/:id/magic-links/:linkId/email', loadClient, requireRole(can.generateMagicLinks), async (req, res) => {
    // Re-send is not possible (tokens are stored hashed); this emails a freshly generated link and revokes the old one.
    const link = getMagicLink(req.ctx, String(req.params.linkId));
    const client = res.locals.client as C.ClientRow;
    if (!link || link.client_id !== client.id) throw new HttpError(404, 'Link not found');
    if (!client.email) throw new HttpError(400, 'Client has no email on file');
    revokeMagicLink(req.ctx, link, req.user!, req.meta.ip);
    const created = createMagicLink(req.ctx, { type: 'returning', clientId: client.id, taxYear: link.tax_year }, req.user!, req.meta.ip);
    await req.ctx.mailer.send(client.email, `${res.locals.firmName}: your secure client portal link`, `Hello ${client.preferred_name || client.legal_name},\n\nUse this secure link to review your information and upload documents for tax year ${link.tax_year}:\n\n${created.url}\n\nThis link expires ${new Date(created.link.expires_at).toUTCString()}. You will be asked to confirm the last 4 digits of your SSN and your date of birth.\n\n${res.locals.firmName}`);
    req.flash('success', `A new link was emailed to ${client.email}.`);
    res.redirect(`/clients/${client.id}#portal`);
  });

  r.get('/:id/audit', loadClient, (req, res) => {
    const page = Math.max(0, parseInt(String(req.query.page || '0'), 10) || 0);
    const { rows, total } = listAudit(req.ctx, { clientId: res.locals.client.id, limit: 100, offset: page * 100 });
    res.render('clients/audit', { title: `Audit: ${res.locals.client.legal_name}`, client: res.locals.client, rows, total, page });
  });

  return r;
}
