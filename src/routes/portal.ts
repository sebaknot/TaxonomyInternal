import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import type { AppContext } from '../context.js';
import { PORTAL_COOKIE, cookieOptions, HttpError, wrap } from '../middleware/index.js';
import { dbRateLimit } from '../middleware/rateLimit.js';
import * as M from '../services/magic.js';
import * as C from '../services/clients.js';
import * as D from '../services/documents.js';
import { audit } from '../services/audit.js';
import { DOCUMENT_CATEGORIES } from '../lib/constants.js';
import { completeSchema } from './documents.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Sections a returning client can confirm or update. */
export const PORTAL_SECTIONS: Record<string, { label: string; fields: (keyof C.ClientInput)[] }> = {
  contact: { label: 'Contact information', fields: ['phone', 'email', 'address_line1', 'address_line2', 'city', 'state', 'zip'] },
  personal: { label: 'Personal information', fields: ['legal_name', 'preferred_name'] },
  filing: { label: 'Filing status & spouse', fields: ['filing_status', 'spouse_name', 'spouse_dob'] },
  dependents: { label: 'Dependents', fields: [] },
};

function clientActor(req: Request, client: { id?: string | null; legal_name: string }): C.Actor {
  return { type: 'client', id: client.id ?? null, label: client.legal_name, ip: req.meta.ip, userAgent: req.meta.userAgent };
}

/** Requires a verified portal session with a client (returning link verified, or intake completed). */
const requireVerified = wrap(async (req: Request, res: Response, next: NextFunction) => {
  if (!req.portalSession || !req.portalLink) return res.status(401).render('portal/expired', { title: 'Session required', reason: 'none' });
  if (!req.portalSession.verified) return res.redirect(req.portalLink.type === 'intake' ? '/portal/identity' : '/portal/verify');
  const clientId = req.portalSession.client_id;
  const client = clientId ? await C.getClient(req.ctx, clientId) : undefined;
  if (!client) return req.portalLink.type === 'intake' ? res.redirect('/portal/intake') : res.status(401).render('portal/expired', { title: 'Session required', reason: 'invalid' });
  res.locals.client = client;
  res.locals.link = req.portalLink;
  next();
});

async function startSession(req: Request, res: Response, link: M.MagicLinkRow) {
  const token = await M.createPortalSession(req.ctx, link, req.meta.ip);
  res.cookie(PORTAL_COOKIE, token, cookieOptions(req.ctx));
}

export function portalRouter(ctx: AppContext) {
  const r = Router();
  const limiter = dbRateLimit(ctx, { name: 'portal', windowMs: 15 * 60_000, max: 40 });
  r.use((_req, res, next) => {
    res.locals.portal = true;
    next();
  });

  // ---------- A. Returning client ----------
  r.get(
    '/r/:token',
    limiter,
    wrap(async (req, res) => {
      const link = await M.findMagicLinkByToken(req.ctx, String(req.params.token));
      const state = link ? M.linkState(link) : 'invalid';
      if (!link || state !== 'valid' || link.type !== 'returning') {
        await audit(req.ctx, { actorType: 'anonymous', action: 'portal.link_rejected', entityType: 'magic_link', entityId: link?.id, clientId: link?.client_id, details: { state }, ip: req.meta.ip });
        return res.status(410).render('portal/expired', { title: 'Link unavailable', reason: state });
      }
      await audit(req.ctx, { actorType: 'anonymous', action: 'portal.link_opened', entityType: 'magic_link', entityId: link.id, clientId: link.client_id, ip: req.meta.ip, userAgent: req.meta.userAgent });
      await startSession(req, res, link);
      res.redirect('/portal/verify');
    }),
  );
  r.get('/verify', (req, res) => {
    if (!req.portalSession || !req.portalLink || req.portalLink.type !== 'returning') return res.status(401).render('portal/expired', { title: 'Link required', reason: 'none' });
    if (req.portalSession.verified) return res.redirect('/portal/home');
    res.render('portal/verify', { title: 'Verify your identity', error: null });
  });
  r.post(
    '/verify',
    limiter,
    wrap(async (req, res) => {
      if (!req.portalSession || !req.portalLink || req.portalLink.type !== 'returning') return res.status(401).render('portal/expired', { title: 'Link required', reason: 'none' });
      const result = await M.verifyReturningClient(req.ctx, req.portalSession, req.portalLink, String(req.body.last4 || ''), String(req.body.dob || ''), req.meta.ip);
      if (result.locked) {
        res.clearCookie(PORTAL_COOKIE, { path: '/' });
        return res.status(403).render('portal/expired', { title: 'Link locked', reason: 'locked' });
      }
      if (!result.ok) return res.status(401).render('portal/verify', { title: 'Verify your identity', error: 'Those details do not match our records. Please try again.' });
      res.redirect('/portal/home');
    }),
  );

  // ---------- B. New client intake ----------
  r.get(
    '/new/:token',
    limiter,
    wrap(async (req, res) => {
      const link = await M.findMagicLinkByToken(req.ctx, String(req.params.token));
      const state = link ? M.linkState(link) : 'invalid';
      if (!link || state !== 'valid' || link.type !== 'intake') {
        await audit(req.ctx, { actorType: 'anonymous', action: 'portal.link_rejected', entityType: 'magic_link', entityId: link?.id, details: { state }, ip: req.meta.ip });
        return res.status(410).render('portal/expired', { title: 'Link unavailable', reason: state });
      }
      await audit(req.ctx, { actorType: 'anonymous', action: 'portal.link_opened', entityType: 'magic_link', entityId: link.id, ip: req.meta.ip, userAgent: req.meta.userAgent });
      await startSession(req, res, link);
      res.redirect('/portal/identity');
    }),
  );
  r.get('/identity', (req, res) => {
    if (!req.portalSession || !req.portalLink || req.portalLink.type !== 'intake') return res.status(401).render('portal/expired', { title: 'Link required', reason: 'none' });
    if (req.portalSession.client_id) return res.redirect('/portal/home');
    res.render('portal/identity', { title: 'Welcome', error: null, form: req.portalSession.intake_identity ? JSON.parse(req.portalSession.intake_identity) : {} });
  });
  r.post(
    '/identity',
    limiter,
    wrap(async (req, res) => {
      if (!req.portalSession || !req.portalLink || req.portalLink.type !== 'intake') return res.status(401).render('portal/expired', { title: 'Link required', reason: 'none' });
      const parsed = z.object({ name: z.string().trim().min(2).max(200), email: z.string().trim().email().max(200), phone: z.string().trim().min(7).max(40) }).safeParse(req.body);
      if (!parsed.success) return res.status(400).render('portal/identity', { title: 'Welcome', error: 'Please provide your full name, a valid email address and a phone number.', form: req.body });
      await M.setIntakeIdentity(req.ctx, req.portalSession, req.portalLink, parsed.data, req.meta.ip);
      res.redirect('/portal/intake');
    }),
  );
  r.get('/intake', (req, res) => {
    if (!req.portalSession || !req.portalLink || req.portalLink.type !== 'intake') return res.status(401).render('portal/expired', { title: 'Link required', reason: 'none' });
    if (!req.portalSession.verified || !req.portalSession.intake_identity) return res.redirect('/portal/identity');
    if (req.portalSession.client_id) return res.redirect('/portal/home');
    res.render('portal/intake', { title: 'New client intake', error: null, identity: JSON.parse(req.portalSession.intake_identity), form: {}, dependents: [] });
  });
  r.post(
    '/intake',
    limiter,
    wrap(async (req, res) => {
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
        const session = req.portalSession;
        const client = await req.ctx.db.tx(async (t) => {
          const tctx = { ...req.ctx, db: t };
          const c = await C.createClient(tctx, input, { type: 'client', id: null, label: identity.name, ip: req.meta.ip, userAgent: req.meta.userAgent }, 'portal_intake');
          for (const d of dependents) await C.addDependent(tctx, c.id, d, clientActor(req, c));
          await M.markIntakeCompleted(tctx, link, c);
          await t.run('UPDATE portal_sessions SET client_id = ? WHERE id = ?', c.id, session.id);
          return c;
        });
        await audit(req.ctx, { actorType: 'client', actorId: client.id, actorLabel: client.legal_name, action: 'portal.intake_submitted', entityType: 'client', entityId: client.id, clientId: client.id, details: { dependents: dependents.length }, ip: req.meta.ip, userAgent: req.meta.userAgent });
        res.redirect('/portal/home?welcome=1');
      } catch (err) {
        res.status(400).render('portal/intake', { title: 'New client intake', error: (err as Error).message, identity, form: b, dependents });
      }
    }),
  );

  // ---------- Shared: home, sections, documents ----------
  r.get(
    '/home',
    requireVerified,
    wrap(async (req, res) => {
      const client = res.locals.client as C.ClientRow;
      const link = res.locals.link as M.MagicLinkRow;
      const confirmed = await req.ctx.db.all<{ section: string; action: string; ts: string }>(
        `SELECT DISTINCT ON (details->>'section') details->>'section' AS section, action, ts FROM audit_log
         WHERE client_id = ? AND actor_type = 'client' AND entity_id = ? AND action IN ('portal.section_confirmed','portal.section_updated')
         ORDER BY details->>'section', ts DESC`,
        client.id,
        link.id,
      );
      const sectionState: Record<string, { action: string; ts: string }> = {};
      for (const row of confirmed) sectionState[row.section] = { action: row.action, ts: row.ts };
      const docs = await req.ctx.db.all(
        `SELECT d.*, v.id AS version_id, v.original_filename, v.uploaded_at FROM documents d JOIN document_versions v ON v.document_id = d.id AND v.uploaded_by_type = 'client' AND v.upload_state = 'complete'
         WHERE d.client_id = ? AND d.tax_year = ? ORDER BY v.uploaded_at DESC`,
        client.id,
        link.tax_year,
      );
      res.render('portal/home', {
        title: 'Your information',
        client,
        link,
        sections: PORTAL_SECTIONS,
        sectionState,
        dependents: await C.listDependents(req.ctx, client.id),
        docs,
        categories: DOCUMENT_CATEGORIES,
        welcome: req.query.welcome === '1',
        maskSsn: C.maskSsn,
      });
    }),
  );

  r.post(
    '/confirm/:section',
    requireVerified,
    wrap(async (req, res) => {
      const section = String(req.params.section);
      if (!PORTAL_SECTIONS[section]) throw new HttpError(404, 'Unknown section');
      const client = res.locals.client as C.ClientRow;
      await audit(req.ctx, { actorType: 'client', actorId: client.id, actorLabel: client.legal_name, action: 'portal.section_confirmed', entityType: 'magic_link', entityId: res.locals.link.id, clientId: client.id, details: { section, label: PORTAL_SECTIONS[section].label, tax_year: res.locals.link.tax_year }, ip: req.meta.ip, userAgent: req.meta.userAgent });
      req.flash('success', `${PORTAL_SECTIONS[section].label}: marked as no changes.`);
      res.redirect('/portal/home');
    }),
  );

  r.get('/update/:section', requireVerified, (req, res) => {
    const section = String(req.params.section);
    if (!PORTAL_SECTIONS[section] || section === 'dependents') throw new HttpError(404, 'Unknown section');
    res.render('portal/update', { title: `Update ${PORTAL_SECTIONS[section].label.toLowerCase()}`, section, def: PORTAL_SECTIONS[section], client: res.locals.client, error: null });
  });
  r.post(
    '/update/:section',
    requireVerified,
    wrap(async (req, res) => {
      const section = String(req.params.section);
      const def = PORTAL_SECTIONS[section];
      if (!def || section === 'dependents') throw new HttpError(404, 'Unknown section');
      const client = res.locals.client as C.ClientRow;
      const patch: Partial<C.ClientInput> = {};
      for (const f of def.fields) (patch as any)[f] = req.body[f] ?? null;
      if (section === 'filing' && req.body.spouse_ssn && String(req.body.spouse_ssn).trim()) patch.spouse_ssn = String(req.body.spouse_ssn);
      try {
        const before = { ...client };
        await C.updateClient(req.ctx, client.id, patch, clientActor(req, client));
        const after = (await C.getClient(req.ctx, client.id))!;
        const changed = def.fields.filter((f) => (before as any)[f] !== (after as any)[f]);
        await audit(req.ctx, { actorType: 'client', actorId: client.id, actorLabel: client.legal_name, action: 'portal.section_updated', entityType: 'magic_link', entityId: res.locals.link.id, clientId: client.id, details: { section, label: def.label, changed_fields: changed, tax_year: res.locals.link.tax_year }, ip: req.meta.ip, userAgent: req.meta.userAgent });
        req.flash('success', `${def.label} updated. Thank you.`);
        res.redirect('/portal/home');
      } catch (err) {
        res.status(400).render('portal/update', { title: `Update ${def.label.toLowerCase()}`, section, def, client: { ...client, ...req.body }, error: (err as Error).message });
      }
    }),
  );

  r.post(
    '/dependents',
    requireVerified,
    wrap(async (req, res) => {
      const client = res.locals.client as C.ClientRow;
      const b = req.body as Record<string, string>;
      try {
        const existing = b.id && UUID.test(b.id) ? await C.getDependent(req.ctx, b.id, client.id) : undefined;
        if (b._action === 'delete') {
          if (!existing) throw new Error('Dependent not found');
          await C.deleteDependent(req.ctx, existing, clientActor(req, client));
        } else if (b.id) {
          if (!existing) throw new Error('Dependent not found');
          await C.updateDependent(req.ctx, existing, { name: b.name, relationship: b.relationship, dob: b.dob, ssn: b.ssn && b.ssn.trim() ? b.ssn : undefined }, clientActor(req, client));
        } else {
          await C.addDependent(req.ctx, client.id, { name: b.name, relationship: b.relationship, dob: b.dob, ssn: b.ssn }, clientActor(req, client));
        }
        await audit(req.ctx, { actorType: 'client', actorId: client.id, actorLabel: client.legal_name, action: 'portal.section_updated', entityType: 'magic_link', entityId: res.locals.link.id, clientId: client.id, details: { section: 'dependents', label: 'Dependents', changed_fields: [b._action === 'delete' ? 'removed' : b.id ? 'updated' : 'added'], tax_year: res.locals.link.tax_year }, ip: req.meta.ip });
        req.flash('success', 'Dependents updated.');
      } catch (err) {
        req.flash('error', (err as Error).message);
      }
      res.redirect('/portal/home#dependents');
    }),
  );

  // ---------- Documents: direct-to-storage encrypted upload (same protocol as staff) ----------
  r.post(
    '/documents/init',
    requireVerified,
    wrap(async (req, res) => {
      const client = res.locals.client as C.ClientRow;
      const link = res.locals.link as M.MagicLinkRow;
      const p = z.object({ filename: z.string().min(1).max(255), size: z.number().int().positive(), mime: z.string().max(100).optional().nullable(), category: z.string().min(1), title: z.string().max(200).optional().nullable() }).safeParse(req.body);
      if (!p.success) throw new HttpError(400, 'Invalid upload request');
      try {
        // Tax year is fixed by the link; clients cannot add versions to staff documents.
        res.json(await D.initUpload(req.ctx, { clientId: client.id, taxYear: link.tax_year, category: p.data.category, originalFilename: p.data.filename, mimeType: p.data.mime ?? null, sizeBytes: p.data.size, title: p.data.title ?? null }, clientActor(req, client)));
      } catch (err) {
        throw new HttpError(400, (err as Error).message);
      }
    }),
  );
  r.post(
    '/documents/:versionId/complete',
    requireVerified,
    wrap(async (req, res) => {
      const client = res.locals.client as C.ClientRow;
      const vid = String(req.params.versionId);
      const p = completeSchema.safeParse(req.body);
      if (!p.success || !UUID.test(vid)) throw new HttpError(400, 'Invalid completion request');
      const v = await D.getVersion(req.ctx, vid);
      if (!v || v.client_id !== client.id || v.uploaded_by_type !== 'client') throw new HttpError(404, 'Upload not found.');
      try {
        await D.completeUpload(req.ctx, vid, { sha256: p.data.sha256, sizeBytes: p.data.size }, clientActor(req, client));
        req.flash('success', `Uploaded ${v.original_filename}. Thank you!`);
        res.json({ ok: true, redirect: '/portal/home#documents' });
      } catch (err) {
        throw new HttpError(400, (err as Error).message);
      }
    }),
  );
  /** Clients may re-download files they uploaded themselves through this link's tax year. */
  r.post(
    '/documents/:versionId/download',
    requireVerified,
    wrap(async (req, res) => {
      const client = res.locals.client as C.ClientRow;
      const vid = String(req.params.versionId);
      const v = UUID.test(vid) ? await D.getVersion(req.ctx, vid) : undefined;
      if (!v || v.client_id !== client.id || v.uploaded_by_type !== 'client' || v.upload_state !== 'complete') throw new HttpError(404, 'File not found.');
      res.json(await D.grantDownload(req.ctx, v, clientActor(req, client), client.id));
    }),
  );

  r.post(
    '/logout',
    wrap(async (req, res) => {
      if (req.portalSession) {
        await M.destroyPortalSession(req.ctx, req.portalSession.id);
        if (req.portalSession.client_id) {
          const c = await C.getClient(req.ctx, req.portalSession.client_id);
          await audit(req.ctx, { actorType: 'client', actorId: c?.id, actorLabel: c?.legal_name ?? 'client', action: 'portal.logout', clientId: c?.id, ip: req.meta.ip });
        }
      }
      res.clearCookie(PORTAL_COOKIE, { path: '/' });
      res.render('portal/expired', { title: 'Signed out', reason: 'logout' });
    }),
  );

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
