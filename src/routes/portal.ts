import { Router, type Request, type Response, type NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import fs from 'node:fs';
import { z } from 'zod';
import { PORTAL_COOKIE, cookieOptions, HttpError, csrfAfterUpload } from '../middleware/index.js';
import * as M from '../services/magic.js';
import * as C from '../services/clients.js';
import * as D from '../services/documents.js';
import { audit } from '../services/audit.js';
import { documentUploader } from '../lib/upload.js';
import { DOCUMENT_CATEGORIES } from '../lib/constants.js';

const limiter = rateLimit({ windowMs: 15 * 60_000, max: 40, standardHeaders: true, legacyHeaders: false, message: 'Too many attempts. Try again later.' });

/** Sections a returning client can confirm or update. */
export const PORTAL_SECTIONS: Record<string, { label: string; fields: (keyof C.ClientInput)[] }> = {
  contact: { label: 'Contact information', fields: ['phone', 'email', 'address_line1', 'address_line2', 'city', 'state', 'zip'] },
  personal: { label: 'Personal information', fields: ['legal_name', 'preferred_name'] },
  filing: { label: 'Filing status & spouse', fields: ['filing_status', 'spouse_name', 'spouse_dob'] },
  dependents: { label: 'Dependents', fields: [] },
};

function clientActor(req: Request, client: C.ClientRow | { id?: string; legal_name: string }): C.Actor {
  return { type: 'client', id: client.id ?? null, label: client.legal_name, ip: req.meta.ip, userAgent: req.meta.userAgent };
}

/** Requires a verified portal session with a client (returning link verified, or intake completed). */
function requireVerified(req: Request, res: Response, next: NextFunction) {
  if (!req.portalSession || !req.portalLink) return res.status(401).render('portal/expired', { title: 'Session required', reason: 'none' });
  if (!req.portalSession.verified) return res.redirect(req.portalLink.type === 'intake' ? '/portal/identity' : '/portal/verify');
  const clientId = req.portalSession.client_id;
  const client = clientId ? C.getClient(req.ctx, clientId) : undefined;
  if (!client) return req.portalLink.type === 'intake' ? res.redirect('/portal/intake') : res.status(401).render('portal/expired', { title: 'Session required', reason: 'invalid' });
  res.locals.client = client;
  res.locals.link = req.portalLink;
  next();
}

function startSession(req: Request, res: Response, link: M.MagicLinkRow) {
  // A fresh session per link visit; any earlier session cookie for another link is replaced.
  const token = M.createPortalSession(req.ctx, link, req.meta.ip);
  res.cookie(PORTAL_COOKIE, token, cookieOptions(req.ctx));
}

export function portalRouter() {
  const r = Router();
  r.use((_req, res, next) => {
    res.locals.portal = true;
    next();
  });
  let uploader: ReturnType<typeof documentUploader> | null = null;
  const single = (req: Request, res: Response, next: NextFunction) => {
    uploader ??= documentUploader(req.ctx);
    uploader.single('file')(req, res, (err) => (err ? next(new HttpError(400, err.message)) : next()));
  };

  // ---------- A. Returning client ----------
  r.get('/r/:token', limiter, (req, res) => {
    const link = M.findMagicLinkByToken(req.ctx, String(req.params.token));
    const state = link ? M.linkState(link) : 'invalid';
    if (!link || state !== 'valid' || link.type !== 'returning') {
      audit(req.ctx, { actorType: 'anonymous', action: 'portal.link_rejected', entityType: 'magic_link', entityId: link?.id, clientId: link?.client_id, details: { state }, ip: req.meta.ip });
      return res.status(410).render('portal/expired', { title: 'Link unavailable', reason: state });
    }
    audit(req.ctx, { actorType: 'anonymous', action: 'portal.link_opened', entityType: 'magic_link', entityId: link.id, clientId: link.client_id, ip: req.meta.ip, userAgent: req.meta.userAgent });
    startSession(req, res, link);
    res.redirect('/portal/verify');
  });
  r.get('/verify', (req, res) => {
    if (!req.portalSession || !req.portalLink || req.portalLink.type !== 'returning') return res.status(401).render('portal/expired', { title: 'Link required', reason: 'none' });
    if (req.portalSession.verified) return res.redirect('/portal/home');
    res.render('portal/verify', { title: 'Verify your identity', error: null });
  });
  r.post('/verify', limiter, (req, res) => {
    if (!req.portalSession || !req.portalLink || req.portalLink.type !== 'returning') return res.status(401).render('portal/expired', { title: 'Link required', reason: 'none' });
    const result = M.verifyReturningClient(req.ctx, req.portalSession, req.portalLink, String(req.body.last4 || ''), String(req.body.dob || ''), req.meta.ip);
    if (result.locked) {
      res.clearCookie(PORTAL_COOKIE, { path: '/' });
      return res.status(403).render('portal/expired', { title: 'Link locked', reason: 'locked' });
    }
    if (!result.ok) return res.status(401).render('portal/verify', { title: 'Verify your identity', error: 'Those details do not match our records. Please try again.' });
    res.redirect('/portal/home');
  });

  // ---------- B. New client intake ----------
  r.get('/new/:token', limiter, (req, res) => {
    const link = M.findMagicLinkByToken(req.ctx, String(req.params.token));
    const state = link ? M.linkState(link) : 'invalid';
    if (!link || state !== 'valid' || link.type !== 'intake') {
      audit(req.ctx, { actorType: 'anonymous', action: 'portal.link_rejected', entityType: 'magic_link', entityId: link?.id, details: { state }, ip: req.meta.ip });
      return res.status(410).render('portal/expired', { title: 'Link unavailable', reason: state });
    }
    audit(req.ctx, { actorType: 'anonymous', action: 'portal.link_opened', entityType: 'magic_link', entityId: link.id, ip: req.meta.ip, userAgent: req.meta.userAgent });
    startSession(req, res, link);
    res.redirect('/portal/identity');
  });
  r.get('/identity', (req, res) => {
    if (!req.portalSession || !req.portalLink || req.portalLink.type !== 'intake') return res.status(401).render('portal/expired', { title: 'Link required', reason: 'none' });
    if (req.portalSession.client_id) return res.redirect('/portal/home');
    res.render('portal/identity', { title: 'Welcome', error: null, form: req.portalSession.intake_identity ? JSON.parse(req.portalSession.intake_identity) : {} });
  });
  r.post('/identity', limiter, (req, res) => {
    if (!req.portalSession || !req.portalLink || req.portalLink.type !== 'intake') return res.status(401).render('portal/expired', { title: 'Link required', reason: 'none' });
    const parsed = z.object({ name: z.string().trim().min(2).max(200), email: z.string().trim().email().max(200), phone: z.string().trim().min(7).max(40) }).safeParse(req.body);
    if (!parsed.success) return res.status(400).render('portal/identity', { title: 'Welcome', error: 'Please provide your full name, a valid email address and a phone number.', form: req.body });
    M.setIntakeIdentity(req.ctx, req.portalSession, req.portalLink, parsed.data, req.meta.ip);
    res.redirect('/portal/intake');
  });
  r.get('/intake', (req, res) => {
    if (!req.portalSession || !req.portalLink || req.portalLink.type !== 'intake') return res.status(401).render('portal/expired', { title: 'Link required', reason: 'none' });
    if (!req.portalSession.verified || !req.portalSession.intake_identity) return res.redirect('/portal/identity');
    if (req.portalSession.client_id) return res.redirect('/portal/home');
    res.render('portal/intake', { title: 'New client intake', error: null, identity: JSON.parse(req.portalSession.intake_identity), form: {}, dependents: [] });
  });
  r.post('/intake', limiter, (req, res) => {
    if (!req.portalSession || !req.portalLink || req.portalLink.type !== 'intake') return res.status(401).render('portal/expired', { title: 'Link required', reason: 'none' });
    if (!req.portalSession.verified || !req.portalSession.intake_identity) return res.redirect('/portal/identity');
    if (req.portalSession.client_id) return res.redirect('/portal/home');
    const identity = JSON.parse(req.portalSession.intake_identity) as { name: string; email: string; phone: string };
    const b = req.body as Record<string, any>;
    const dependents = collectDependents(b);
    try {
      const input: C.ClientInput = {
        legal_name: String(b.legal_name || identity.name),
        preferred_name: b.preferred_name,
        ssn: b.ssn,
        dob: b.dob,
        phone: b.phone || identity.phone,
        email: b.email || identity.email,
        address_line1: b.address_line1,
        address_line2: b.address_line2,
        city: b.city,
        state: b.state,
        zip: b.zip,
        filing_status: b.filing_status,
        spouse_name: b.spouse_name,
        spouse_ssn: b.spouse_ssn,
        spouse_dob: b.spouse_dob,
        source: 'Website',
        notes: b.message ? `Client intake message: ${String(b.message).slice(0, 2000)}` : null,
      };
      if (!input.dob) throw new Error('Date of birth is required.');
      const link = req.portalLink;
      const client = req.ctx.db.transaction(() => {
        const c = C.createClient(req.ctx, input, { type: 'client', id: null, label: identity.name, ip: req.meta.ip, userAgent: req.meta.userAgent }, 'portal_intake');
        for (const d of dependents) C.addDependent(req.ctx, c.id, d, clientActor(req, c));
        M.markIntakeCompleted(req.ctx, link, c);
        req.ctx.db.prepare('UPDATE portal_sessions SET client_id = ? WHERE id = ?').run(c.id, req.portalSession!.id);
        return c;
      })();
      audit(req.ctx, { actorType: 'client', actorId: client.id, actorLabel: client.legal_name, action: 'portal.intake_submitted', entityType: 'client', entityId: client.id, clientId: client.id, details: { dependents: dependents.length }, ip: req.meta.ip, userAgent: req.meta.userAgent });
      res.redirect('/portal/home?welcome=1');
    } catch (err) {
      res.status(400).render('portal/intake', { title: 'New client intake', error: (err as Error).message, identity, form: b, dependents });
    }
  });

  // ---------- Shared: home, sections, documents ----------
  r.get('/home', requireVerified, (req, res) => {
    const client = res.locals.client as C.ClientRow;
    const link = res.locals.link as M.MagicLinkRow;
    const confirmed = req.ctx.db
      .prepare("SELECT action, details, MAX(ts) ts FROM audit_log WHERE client_id = ? AND actor_type = 'client' AND entity_id = ? AND action IN ('portal.section_confirmed','portal.section_updated') GROUP BY json_extract(details, '$.section')")
      .all(client.id, link.id) as { action: string; details: string; ts: string }[];
    const sectionState: Record<string, { action: string; ts: string }> = {};
    for (const row of confirmed) sectionState[JSON.parse(row.details).section] = { action: row.action, ts: row.ts };
    const docs = req.ctx.db
      .prepare(`SELECT d.*, v.original_filename, v.uploaded_at FROM documents d JOIN document_versions v ON v.document_id = d.id AND v.uploaded_by_type = 'client'
                WHERE d.client_id = ? AND d.tax_year = ? ORDER BY v.uploaded_at DESC`)
      .all(client.id, link.tax_year);
    res.render('portal/home', {
      title: 'Your information',
      client,
      link,
      sections: PORTAL_SECTIONS,
      sectionState,
      dependents: C.listDependents(req.ctx, client.id),
      docs,
      categories: DOCUMENT_CATEGORIES,
      welcome: req.query.welcome === '1',
      maskSsn: C.maskSsn,
    });
  });

  r.post('/confirm/:section', requireVerified, (req, res) => {
    const section = String(req.params.section);
    if (!PORTAL_SECTIONS[section]) throw new HttpError(404, 'Unknown section');
    const client = res.locals.client as C.ClientRow;
    audit(req.ctx, { actorType: 'client', actorId: client.id, actorLabel: client.legal_name, action: 'portal.section_confirmed', entityType: 'magic_link', entityId: res.locals.link.id, clientId: client.id, details: { section, label: PORTAL_SECTIONS[section].label, tax_year: res.locals.link.tax_year }, ip: req.meta.ip, userAgent: req.meta.userAgent });
    req.flash('success', `${PORTAL_SECTIONS[section].label}: marked as no changes.`);
    res.redirect('/portal/home');
  });

  r.get('/update/:section', requireVerified, (req, res) => {
    const section = String(req.params.section);
    if (!PORTAL_SECTIONS[section] || section === 'dependents') throw new HttpError(404, 'Unknown section');
    res.render('portal/update', { title: `Update ${PORTAL_SECTIONS[section].label.toLowerCase()}`, section, def: PORTAL_SECTIONS[section], client: res.locals.client, error: null });
  });
  r.post('/update/:section', requireVerified, (req, res) => {
    const section = String(req.params.section);
    const def = PORTAL_SECTIONS[section];
    if (!def || section === 'dependents') throw new HttpError(404, 'Unknown section');
    const client = res.locals.client as C.ClientRow;
    const patch: Partial<C.ClientInput> = {};
    for (const f of def.fields) (patch as any)[f] = req.body[f] ?? null;
    if (section === 'filing' && req.body.spouse_ssn && String(req.body.spouse_ssn).trim()) patch.spouse_ssn = String(req.body.spouse_ssn);
    try {
      const before = { ...client };
      C.updateClient(req.ctx, client.id, patch, clientActor(req, client));
      const after = C.getClient(req.ctx, client.id)!;
      const changed = def.fields.filter((f) => (before as any)[f] !== (after as any)[f]);
      audit(req.ctx, { actorType: 'client', actorId: client.id, actorLabel: client.legal_name, action: 'portal.section_updated', entityType: 'magic_link', entityId: res.locals.link.id, clientId: client.id, details: { section, label: def.label, changed_fields: changed, tax_year: res.locals.link.tax_year }, ip: req.meta.ip, userAgent: req.meta.userAgent });
      req.flash('success', `${def.label} updated. Thank you.`);
      res.redirect('/portal/home');
    } catch (err) {
      res.status(400).render('portal/update', { title: `Update ${def.label.toLowerCase()}`, section, def, client: { ...client, ...req.body }, error: (err as Error).message });
    }
  });

  // Dependents: add / edit / remove through the portal
  r.post('/dependents', requireVerified, (req, res) => {
    const client = res.locals.client as C.ClientRow;
    const b = req.body as Record<string, string>;
    try {
      if (b._action === 'delete') {
        const dep = req.ctx.db.prepare('SELECT * FROM dependents WHERE id = ? AND client_id = ?').get(String(b.id), client.id) as C.DependentRow | undefined;
        if (!dep) throw new Error('Dependent not found');
        C.deleteDependent(req.ctx, dep, clientActor(req, client));
      } else if (b.id) {
        const dep = req.ctx.db.prepare('SELECT * FROM dependents WHERE id = ? AND client_id = ?').get(String(b.id), client.id) as C.DependentRow | undefined;
        if (!dep) throw new Error('Dependent not found');
        C.updateDependent(req.ctx, dep, { name: b.name, relationship: b.relationship, dob: b.dob, ssn: b.ssn && b.ssn.trim() ? b.ssn : undefined }, clientActor(req, client));
      } else {
        C.addDependent(req.ctx, client.id, { name: b.name, relationship: b.relationship, dob: b.dob, ssn: b.ssn }, clientActor(req, client));
      }
      audit(req.ctx, { actorType: 'client', actorId: client.id, actorLabel: client.legal_name, action: 'portal.section_updated', entityType: 'magic_link', entityId: res.locals.link.id, clientId: client.id, details: { section: 'dependents', label: 'Dependents', changed_fields: [b._action === 'delete' ? 'removed' : b.id ? 'updated' : 'added'], tax_year: res.locals.link.tax_year }, ip: req.meta.ip });
      req.flash('success', 'Dependents updated.');
    } catch (err) {
      req.flash('error', (err as Error).message);
    }
    res.redirect('/portal/home#dependents');
  });

  // Document upload: lands in the vault under the link's tax year.
  r.post('/documents', single, csrfAfterUpload, requireVerified, async (req, res) => {
    const client = res.locals.client as C.ClientRow;
    const link = res.locals.link as M.MagicLinkRow;
    const file = req.file;
    if (!file) {
      req.flash('error', 'Choose a file to upload.');
      return res.redirect('/portal/home#documents');
    }
    try {
      await D.uploadDocument(req.ctx, { clientId: client.id, taxYear: link.tax_year, category: String(req.body.category || 'Other'), tempPath: file.path, originalFilename: file.originalname, mimeType: file.mimetype, title: req.body.description ? String(req.body.description) : null }, clientActor(req, client));
      req.flash('success', `Uploaded ${file.originalname}. Thank you!`);
    } catch (err) {
      fs.rmSync(file.path, { force: true });
      req.flash('error', (err as Error).message);
    }
    res.redirect('/portal/home#documents');
  });

  r.post('/logout', (req, res) => {
    if (req.portalSession) {
      M.destroyPortalSession(req.ctx, req.portalSession.id);
      if (req.portalSession.client_id) {
        const c = C.getClient(req.ctx, req.portalSession.client_id);
        audit(req.ctx, { actorType: 'client', actorId: c?.id, actorLabel: c?.legal_name ?? 'client', action: 'portal.logout', clientId: c?.id, ip: req.meta.ip });
      }
    }
    res.clearCookie(PORTAL_COOKIE, { path: '/' });
    res.render('portal/expired', { title: 'Signed out', reason: 'logout' });
  });

  return r;
}

function collectDependents(b: Record<string, any>): { name: string; relationship?: string; dob?: string; ssn?: string }[] {
  const out: { name: string; relationship?: string; dob?: string; ssn?: string }[] = [];
  const names = ([] as string[]).concat(b['dep_name'] ?? []);
  const rels = ([] as string[]).concat(b['dep_relationship'] ?? []);
  const dobs = ([] as string[]).concat(b['dep_dob'] ?? []);
  const ssns = ([] as string[]).concat(b['dep_ssn'] ?? []);
  names.forEach((n, i) => {
    if (String(n || '').trim()) out.push({ name: String(n).trim(), relationship: rels[i], dob: dobs[i], ssn: ssns[i] });
  });
  return out;
}
