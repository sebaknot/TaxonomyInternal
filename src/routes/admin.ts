import { Router } from 'express';
import { z } from 'zod';
import { HttpError, requireRole } from '../middleware/index.js';
import { can } from '../services/permissions.js';
import * as A from '../services/auth.js';
import { listAudit } from '../services/audit.js';
import { allSettings, setSetting } from '../services/settings.js';
import { audit } from '../services/audit.js';
import { ROLES, SETTING_KEYS, type Role } from '../lib/constants.js';
import { createTag, listTags } from '../services/clients.js';

export function adminRouter() {
  const r = Router();
  r.use(requireRole(can.manageUsers));

  r.get('/', (req, res) => {
    const openAlerts = (req.ctx.db.prepare('SELECT COUNT(*) c FROM admin_alerts WHERE acknowledged_at IS NULL').get() as any).c;
    res.render('admin/index', { title: 'Administration', openAlerts });
  });

  // ----- Users -----
  r.get('/users', (req, res) => {
    const sessions = req.ctx.db.prepare('SELECT user_id, COUNT(*) c FROM sessions WHERE mfa_passed = 1 GROUP BY user_id').all() as { user_id: string; c: number }[];
    res.render('admin/users', { title: 'Staff users', users: A.listUsers(req.ctx), sessionCounts: Object.fromEntries(sessions.map((s) => [s.user_id, s.c])) });
  });
  r.get('/users/new', (req, res) => res.render('admin/user_form', { title: 'New user', u: null, error: null }));
  r.post('/users', (req, res) => {
    const parsed = z.object({ email: z.string().trim().email(), name: z.string().trim().min(1).max(200), role: z.enum(ROLES), password: z.string().max(500) }).safeParse(req.body);
    if (!parsed.success) return res.status(400).render('admin/user_form', { title: 'New user', u: null, error: 'Check the email, name and role.' });
    try {
      const u = A.createUser(req.ctx, parsed.data, req.user!);
      req.flash('success', `User ${u.email} created. They will be asked to set up two-factor authentication at first sign-in.`);
      res.redirect(`/admin/users/${u.id}`);
    } catch (err) {
      res.status(400).render('admin/user_form', { title: 'New user', u: null, error: (err as Error).message });
    }
  });
  r.get('/users/:id', (req, res, next) => {
    const u = A.getUserById(req.ctx, String(req.params.id));
    if (!u) return next(new HttpError(404, 'User not found'));
    const devices = req.ctx.db.prepare('SELECT * FROM user_devices WHERE user_id = ? ORDER BY last_seen_at DESC').all(u.id);
    const locations = req.ctx.db.prepare('SELECT * FROM user_locations WHERE user_id = ? ORDER BY last_seen_at DESC').all(u.id);
    const sessions = req.ctx.db.prepare('SELECT * FROM sessions WHERE user_id = ? ORDER BY last_activity_at DESC').all(u.id);
    const recent = listAudit(req.ctx, { actorId: u.id, limit: 30 }).rows;
    res.render('admin/user_show', { title: u.name, u, devices, locations, sessions, recent, error: null });
  });
  r.post('/users/:id', (req, res, next) => {
    const u = A.getUserById(req.ctx, String(req.params.id));
    if (!u) return next(new HttpError(404, 'User not found'));
    const action = String(req.body._action || 'update');
    try {
      switch (action) {
        case 'update': {
          const parsed = z.object({ email: z.string().trim().email(), name: z.string().trim().min(1).max(200), role: z.enum(ROLES) }).safeParse(req.body);
          if (!parsed.success) throw new Error('Check the email, name and role.');
          if (u.id === req.user!.id && parsed.data.role !== 'admin') throw new Error('You cannot remove your own admin role.');
          A.updateUser(req.ctx, u.id, parsed.data, req.user!);
          req.flash('success', 'User updated.');
          break;
        }
        case 'revoke':
          if (u.id === req.user!.id) throw new Error('You cannot revoke your own access.');
          A.revokeUser(req.ctx, u.id, req.user!, req.meta.ip);
          req.flash('success', `${u.email} has been revoked. All their sessions were terminated.`);
          break;
        case 'reinstate':
          A.reinstateUser(req.ctx, u.id, req.user!, req.meta.ip);
          req.flash('success', `${u.email} reinstated.`);
          break;
        case 'reset_mfa':
          A.resetUserMfa(req.ctx, u.id, req.user!, req.meta.ip);
          req.flash('success', `${u.email} must re-enroll two-factor authentication at next sign-in.`);
          break;
        case 'reset_password':
          A.setUserPassword(req.ctx, u.id, String(req.body.password || ''), req.user!);
          req.flash('success', `Password reset for ${u.email}. Their sessions were terminated.`);
          break;
        case 'end_sessions':
          req.ctx.db.prepare('DELETE FROM sessions WHERE user_id = ?').run(u.id);
          audit(req.ctx, { actorType: 'user', actorId: req.user!.id, actorLabel: req.user!.email, action: 'user.sessions_terminated', entityType: 'user', entityId: u.id, ip: req.meta.ip });
          req.flash('success', 'All sessions ended.');
          break;
        default:
          throw new Error('Unknown action');
      }
    } catch (err) {
      req.flash('error', (err as Error).message);
    }
    res.redirect(`/admin/users/${u.id}`);
  });

  // ----- Audit log -----
  r.get('/audit', (req, res) => {
    const page = Math.max(0, parseInt(String(req.query.page || '0'), 10) || 0);
    const filter = String(req.query.filter || '');
    const prefixes: Record<string, string> = { auth: 'auth.', ssn: 'client.ssn_reveal', clients: 'client.', documents: 'document.', portal: 'portal.', users: 'user.', links: 'magic_link.', imports: 'import.' };
    const { rows, total } = listAudit(req.ctx, { actionPrefix: prefixes[filter], limit: 100, offset: page * 100 });
    res.render('admin/audit', { title: 'Audit log', rows, total, page, filter, filters: Object.keys(prefixes) });
  });

  // ----- Alerts -----
  r.get('/alerts', (req, res) => {
    const alerts = req.ctx.db.prepare('SELECT a.*, u.name user_name FROM admin_alerts a LEFT JOIN users u ON u.id = a.user_id ORDER BY (acknowledged_at IS NULL) DESC, ts DESC LIMIT 300').all();
    res.render('admin/alerts', { title: 'Security alerts', alerts });
  });
  r.post('/alerts/:id/ack', (req, res) => {
    req.ctx.db.prepare("UPDATE admin_alerts SET acknowledged_at = datetime('now'), acknowledged_by = ? WHERE id = ? AND acknowledged_at IS NULL").run(req.user!.email, String(req.params.id));
    res.redirect('/admin/alerts');
  });

  // ----- Settings -----
  r.get('/settings', (req, res) => res.render('admin/settings', { title: 'Settings', values: allSettings(req.ctx), error: null }));
  r.post('/settings', (req, res) => {
    const parsed = z
      .object({
        session_idle_minutes: z.coerce.number().int().min(1).max(240),
        magic_link_valid_hours: z.coerce.number().int().min(1).max(720),
        current_tax_year: z.coerce.number().int().min(2000).max(2100),
        firm_name: z.string().trim().min(1).max(100),
      })
      .safeParse(req.body);
    if (!parsed.success) return res.status(400).render('admin/settings', { title: 'Settings', values: allSettings(req.ctx), error: 'Check the values: idle timeout 1–240 minutes, link validity 1–720 hours.' });
    const before = allSettings(req.ctx);
    for (const [k, v] of Object.entries(parsed.data)) setSetting(req.ctx, k, String(v));
    audit(req.ctx, { actorType: 'user', actorId: req.user!.id, actorLabel: req.user!.email, action: 'settings.update', entityType: 'settings', details: { before: { session_idle_minutes: before[SETTING_KEYS.sessionIdleMinutes], magic_link_valid_hours: before[SETTING_KEYS.magicLinkHours], current_tax_year: before[SETTING_KEYS.currentTaxYear], firm_name: before.firm_name }, after: parsed.data }, ip: req.meta.ip });
    req.flash('success', 'Settings saved.');
    res.redirect('/admin/settings');
  });

  // ----- Tags -----
  r.get('/tags', (req, res) => res.render('admin/tags', { title: 'Specialization tags', tags: listTags(req.ctx) }));
  r.post('/tags', (req, res) => {
    const name = String(req.body.name || '').trim().slice(0, 60);
    if (name) createTag(req.ctx, name);
    res.redirect('/admin/tags');
  });

  // ----- Email outbox -----
  r.get('/outbox', (req, res) => {
    const emails = req.ctx.db.prepare('SELECT id, ts, to_addr, subject, sent_at, error FROM email_outbox ORDER BY ts DESC LIMIT 200').all();
    res.render('admin/outbox', { title: 'Email outbox', emails, smtpConfigured: !!req.ctx.config.smtp });
  });
  r.get('/outbox/:id', (req, res, next) => {
    const email = req.ctx.db.prepare('SELECT * FROM email_outbox WHERE id = ?').get(String(req.params.id));
    if (!email) return next(new HttpError(404, 'Not found'));
    res.render('admin/outbox_show', { title: 'Email', email });
  });

  return r;
}
