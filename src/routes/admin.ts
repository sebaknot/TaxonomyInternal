import { Router } from 'express';
import { z } from 'zod';
import { HttpError, requireRole, wrap } from '../middleware/index.js';
import { can } from '../services/permissions.js';
import * as A from '../services/auth.js';
import { listAudit, audit } from '../services/audit.js';
import { allSettings, setSetting } from '../services/settings.js';
import { ROLES, SETTING_KEYS } from '../lib/constants.js';
import { createTag, listTags } from '../services/clients.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function adminRouter() {
  const r = Router();
  r.use(requireRole(can.manageUsers));

  r.get(
    '/',
    wrap(async (req, res) => {
      const openAlerts = await req.ctx.db.scalar<number>('SELECT COUNT(*) FROM admin_alerts WHERE acknowledged_at IS NULL');
      res.render('admin/index', { title: 'Administration', openAlerts });
    }),
  );

  // ----- Users -----
  r.get(
    '/users',
    wrap(async (req, res) => {
      const sessions = await req.ctx.db.all<{ user_id: string; c: number }>('SELECT user_id, COUNT(*) c FROM sessions WHERE mfa_passed = true GROUP BY user_id');
      res.render('admin/users', { title: 'Staff users', users: await A.listUsers(req.ctx), sessionCounts: Object.fromEntries(sessions.map((s) => [s.user_id, s.c])) });
    }),
  );
  r.get('/users/new', (_req, res) => res.render('admin/user_form', { title: 'New user', u: null, error: null }));
  r.post(
    '/users',
    wrap(async (req, res) => {
      const parsed = z.object({ email: z.string().trim().email(), name: z.string().trim().min(1).max(200), role: z.enum(ROLES), password: z.string().max(500) }).safeParse(req.body);
      if (!parsed.success) return res.status(400).render('admin/user_form', { title: 'New user', u: null, error: 'Check the email, name and role.' });
      try {
        const u = await A.createUser(req.ctx, parsed.data, req.user!);
        req.flash('success', `User ${u.email} created. They will be asked to set up two-factor authentication at first sign-in.`);
        res.redirect(`/admin/users/${u.id}`);
      } catch (err) {
        res.status(400).render('admin/user_form', { title: 'New user', u: null, error: (err as Error).message });
      }
    }),
  );
  r.get(
    '/users/:id',
    wrap(async (req, res, next) => {
      const id = String(req.params.id);
      const u = UUID.test(id) ? await A.getUserById(req.ctx, id) : undefined;
      if (!u) return next(new HttpError(404, 'User not found'));
      const devices = await req.ctx.db.all('SELECT * FROM user_devices WHERE user_id = ? ORDER BY last_seen_at DESC', u.id);
      const locations = await req.ctx.db.all('SELECT * FROM user_locations WHERE user_id = ? ORDER BY last_seen_at DESC', u.id);
      const sessions = await req.ctx.db.all('SELECT * FROM sessions WHERE user_id = ? ORDER BY last_activity_at DESC', u.id);
      const recent = (await listAudit(req.ctx, { actorId: u.id, limit: 30 })).rows;
      res.render('admin/user_show', { title: u.name, u, devices, locations, sessions, recent, error: null });
    }),
  );
  r.post(
    '/users/:id',
    wrap(async (req, res, next) => {
      const id = String(req.params.id);
      const u = UUID.test(id) ? await A.getUserById(req.ctx, id) : undefined;
      if (!u) return next(new HttpError(404, 'User not found'));
      const action = String(req.body._action || 'update');
      try {
        switch (action) {
          case 'update': {
            const parsed = z.object({ email: z.string().trim().email(), name: z.string().trim().min(1).max(200), role: z.enum(ROLES) }).safeParse(req.body);
            if (!parsed.success) throw new Error('Check the email, name and role.');
            if (u.id === req.user!.id && parsed.data.role !== 'admin') throw new Error('You cannot remove your own admin role.');
            await A.updateUser(req.ctx, u.id, parsed.data, req.user!);
            req.flash('success', 'User updated.');
            break;
          }
          case 'revoke':
            if (u.id === req.user!.id) throw new Error('You cannot revoke your own access.');
            await A.revokeUser(req.ctx, u.id, req.user!, req.meta.ip);
            req.flash('success', `${u.email} has been revoked. All their sessions were terminated.`);
            break;
          case 'reinstate':
            await A.reinstateUser(req.ctx, u.id, req.user!, req.meta.ip);
            req.flash('success', `${u.email} reinstated.`);
            break;
          case 'reset_mfa':
            await A.resetUserMfa(req.ctx, u.id, req.user!, req.meta.ip);
            req.flash('success', `${u.email} must re-enroll two-factor authentication at next sign-in.`);
            break;
          case 'reset_password':
            await A.setUserPassword(req.ctx, u.id, String(req.body.password || ''), req.user!);
            req.flash('success', `Password reset for ${u.email}. Their sessions were terminated.`);
            break;
          case 'end_sessions':
            await req.ctx.db.run('DELETE FROM sessions WHERE user_id = ?', u.id);
            await audit(req.ctx, { actorType: 'user', actorId: req.user!.id, actorLabel: req.user!.email, action: 'user.sessions_terminated', entityType: 'user', entityId: u.id, ip: req.meta.ip });
            req.flash('success', 'All sessions ended.');
            break;
          default:
            throw new Error('Unknown action');
        }
      } catch (err) {
        req.flash('error', (err as Error).message);
      }
      res.redirect(`/admin/users/${u.id}`);
    }),
  );

  // ----- Audit log -----
  r.get(
    '/audit',
    wrap(async (req, res) => {
      const page = Math.max(0, parseInt(String(req.query.page || '0'), 10) || 0);
      const filter = String(req.query.filter || '');
      const prefixes: Record<string, string> = { auth: 'auth.', ssn: 'client.ssn_reveal', clients: 'client.', documents: 'document.', portal: 'portal.', users: 'user.', links: 'magic_link.', imports: 'import.' };
      const { rows, total } = await listAudit(req.ctx, { actionPrefix: prefixes[filter], limit: 100, offset: page * 100 });
      res.render('admin/audit', { title: 'Audit log', rows, total, page, filter, filters: Object.keys(prefixes) });
    }),
  );

  // ----- Alerts -----
  r.get(
    '/alerts',
    wrap(async (req, res) => {
      const alerts = await req.ctx.db.all('SELECT a.*, u.name user_name FROM admin_alerts a LEFT JOIN users u ON u.id = a.user_id ORDER BY (acknowledged_at IS NULL) DESC, ts DESC LIMIT 300');
      res.render('admin/alerts', { title: 'Security alerts', alerts });
    }),
  );
  r.post(
    '/alerts/:id/ack',
    wrap(async (req, res) => {
      const id = String(req.params.id);
      if (UUID.test(id)) {
        const n = await req.ctx.db.run('UPDATE admin_alerts SET acknowledged_at = now(), acknowledged_by = ? WHERE id = ? AND acknowledged_at IS NULL', req.user!.email, id);
        if (n) {
          await audit(req.ctx, { actorType: 'user', actorId: req.user!.id, actorLabel: req.user!.email, action: 'alert.acknowledge', entityType: 'alert', entityId: id, ip: req.meta.ip });
          req.flash('success', 'Alert acknowledged.');
        }
      }
      res.redirect('/admin/alerts');
    }),
  );

  // ----- Settings -----
  r.get(
    '/settings',
    wrap(async (req, res) => res.render('admin/settings', { title: 'Settings', values: await allSettings(req.ctx), error: null })),
  );
  r.post(
    '/settings',
    wrap(async (req, res) => {
      const parsed = z
        .object({
          session_idle_minutes: z.coerce.number().int().min(1).max(240),
          magic_link_valid_hours: z.coerce.number().int().min(1).max(720),
          current_tax_year: z.coerce.number().int().min(2000).max(2100),
          firm_name: z.string().trim().min(1).max(100),
        })
        .safeParse(req.body);
      if (!parsed.success) return res.status(400).render('admin/settings', { title: 'Settings', values: await allSettings(req.ctx), error: 'Check the values: idle timeout 1–240 minutes, link validity 1–720 hours.' });
      const before = await allSettings(req.ctx);
      for (const [k, v] of Object.entries(parsed.data)) await setSetting(req.ctx, k, String(v));
      await audit(req.ctx, {
        actorType: 'user',
        actorId: req.user!.id,
        actorLabel: req.user!.email,
        action: 'settings.update',
        entityType: 'settings',
        details: { before: { session_idle_minutes: before[SETTING_KEYS.sessionIdleMinutes], magic_link_valid_hours: before[SETTING_KEYS.magicLinkHours], current_tax_year: before[SETTING_KEYS.currentTaxYear], firm_name: before.firm_name }, after: parsed.data },
        ip: req.meta.ip,
      });
      req.flash('success', 'Settings saved.');
      res.redirect('/admin/settings');
    }),
  );

  r.post(
    '/settings/test-email',
    wrap(async (req, res) => {
      const parsed = z.object({ to: z.string().trim().email().max(200) }).safeParse(req.body);
      if (!parsed.success) {
        req.flash('error', 'Enter a valid email address.');
        return res.redirect('/admin/settings');
      }
      const result = await req.ctx.mailer.sendTest(parsed.data.to);
      await audit(req.ctx, { actorType: 'user', actorId: req.user!.id, actorLabel: req.user!.email, action: 'email.test', entityType: 'email', details: { to: parsed.data.to, ok: result.ok, error: result.error }, ip: req.meta.ip });
      if (result.ok) req.flash('success', `Test email sent to ${parsed.data.to}.`);
      else req.flash('error', `Test email failed: ${result.error}`);
      res.redirect('/admin/settings');
    }),
  );

  // ----- Tags -----
  r.get(
    '/tags',
    wrap(async (req, res) => res.render('admin/tags', { title: 'Specialization tags', tags: await listTags(req.ctx) })),
  );
  r.post(
    '/tags',
    wrap(async (req, res) => {
      const name = String(req.body.name || '').trim().slice(0, 60);
      if (name) await createTag(req.ctx, name);
      res.redirect('/admin/tags');
    }),
  );

  // ----- Email outbox -----
  r.get(
    '/outbox',
    wrap(async (req, res) => {
      const emails = await req.ctx.db.all('SELECT id, ts, to_addr, subject, status, attempts, last_error, sent_at FROM email_outbox ORDER BY ts DESC LIMIT 200');
      res.render('admin/outbox', { title: 'Email outbox', emails });
    }),
  );
  r.post(
    '/outbox/:id/retry',
    wrap(async (req, res, next) => {
      const id = String(req.params.id);
      const row = UUID.test(id) ? await req.ctx.db.one<{ status: string; to_addr: string }>('SELECT status, to_addr FROM email_outbox WHERE id = ?', id) : undefined;
      if (!row) return next(new HttpError(404, 'Not found'));
      if (row.status === 'sent') {
        req.flash('info', 'That message was already delivered.');
        return res.redirect('/admin/outbox');
      }
      const result = await req.ctx.mailer.retry(id);
      await audit(req.ctx, { actorType: 'user', actorId: req.user!.id, actorLabel: req.user!.email, action: 'email.retry', entityType: 'email', entityId: id, details: { to: row.to_addr, status: result.status, error: result.error }, ip: req.meta.ip });
      if (result.status === 'sent') req.flash('success', `Delivered to ${row.to_addr}.`);
      else req.flash('error', result.status === 'queued' ? 'Email is not configured; the message stays queued.' : `Delivery failed again: ${result.error}`);
      res.redirect('/admin/outbox');
    }),
  );
  r.get(
    '/outbox/:id',
    wrap(async (req, res, next) => {
      const id = String(req.params.id);
      const email = UUID.test(id) ? await req.ctx.db.one('SELECT * FROM email_outbox WHERE id = ?', id) : undefined;
      if (!email) return next(new HttpError(404, 'Not found'));
      res.render('admin/outbox_show', { title: 'Email', email });
    }),
  );

  return r;
}
