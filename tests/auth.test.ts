import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestApp, Client, seedUser, login, PASSWORD, totpCode, type TestApp } from './helpers.js';
import { setSetting } from '../src/services/settings.js';

let app: TestApp;
before(async () => {
  app = await startTestApp();
});
after(async () => app.close());

test('unauthenticated requests are redirected to login; protected pages are not served', async () => {
  const c = new Client(app.baseUrl);
  const r = await c.get('/clients');
  assert.equal(r.status, 302);
  assert.match(r.location!, /^\/login/);
});

test('wrong password fails and is audited; correct password alone does not grant access (MFA required)', async () => {
  const { user, secret } = await seedUser(app.ctx, 'mfa@example.com', 'admin');
  const c = new Client(app.baseUrl);
  const bad = await c.post('/login', { email: user.email, password: 'nope-nope-nope-1' });
  assert.equal(bad.status, 401);
  assert.equal(await app.ctx.db.scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'auth.login_failed' AND actor_id = ?", user.id), 1);

  const ok = await c.post('/login', { email: user.email, password: PASSWORD });
  assert.equal(ok.status, 302);
  assert.match(ok.location!, /^\/mfa/);
  const blocked = await c.get('/clients');
  assert.equal(blocked.status, 302);
  assert.equal(blocked.location, '/mfa');
  await c.get('/mfa');
  assert.equal((await c.post('/mfa', { code: '000000' })).status, 401);
  assert.equal((await c.post('/mfa', { code: totpCode(secret) })).status, 302);
  const home = await c.get('/');
  assert.equal(home.status, 200);
  assert.match(home.text, /Welcome, mfa/);
  assert.equal(await app.ctx.db.scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'auth.login' AND actor_id = ?", user.id), 1);
});

test('a new user must enroll MFA before reaching anything; backup codes work once', async () => {
  const { createUser } = await import('../src/services/auth.js');
  const u = await createUser(app.ctx, { email: 'fresh@example.com', name: 'Fresh', role: 'manager', password: PASSWORD }, null);
  const c = new Client(app.baseUrl);
  await c.post('/login', { email: u.email, password: PASSWORD });
  const setup = await c.get('/mfa');
  assert.equal(setup.status, 200);
  assert.match(setup.text, /Set up two-factor authentication/);
  const secret = setup.text.match(/class="mono">([A-Z2-7]+)</)![1];
  const done = await c.post('/mfa/setup', { code: totpCode(secret) });
  assert.equal(done.status, 200);
  assert.match(done.text, /Backup codes/);
  const codes = [...done.text.matchAll(/<li>([a-z0-9]{8})<\/li>/g)].map((m) => m[1]);
  assert.equal(codes.length, 8);
  assert.equal((await c.get('/')).status, 200);

  await c.post('/logout');
  const c2 = new Client(app.baseUrl);
  await c2.post('/login', { email: u.email, password: PASSWORD });
  await c2.get('/mfa');
  assert.equal((await c2.post('/mfa', { code: codes[0] })).status, 302);
  assert.equal((await c2.get('/')).status, 200);
  const c3 = new Client(app.baseUrl);
  await c3.post('/login', { email: u.email, password: PASSWORD });
  await c3.get('/mfa');
  assert.equal((await c3.post('/mfa', { code: codes[0] })).status, 401);
});

test('idle timeout signs the user out and is configurable by admin', async () => {
  const { user, secret } = await seedUser(app.ctx, 'idle@example.com', 'admin');
  const c = await login(new Client(app.baseUrl), user.email, secret);
  assert.equal((await c.get('/')).status, 200);
  await app.ctx.db.run("UPDATE sessions SET last_activity_at = now() - interval '16 minutes' WHERE user_id = ?", user.id);
  const r = await c.get('/clients');
  assert.equal(r.status, 302);
  assert.match(r.location!, /^\/login/);
  const logout = await app.ctx.db.one<{ details: string }>("SELECT details FROM audit_log WHERE action = 'auth.logout' AND actor_id = ? ORDER BY id DESC", user.id);
  assert.match(logout!.details, /idle_timeout/);

  const c2 = await login(new Client(app.baseUrl), user.email, secret);
  await c2.get('/admin/settings');
  assert.equal((await c2.post('/admin/settings', { session_idle_minutes: '60', magic_link_valid_hours: '72', current_tax_year: '2025', firm_name: 'Taxonomy' })).status, 302);
  await app.ctx.db.run("UPDATE sessions SET last_activity_at = now() - interval '16 minutes' WHERE user_id = ?", user.id);
  assert.equal((await c2.get('/clients')).status, 200);
  await setSetting(app.ctx, 'session_idle_minutes', '15');
});

test('login from a new device / location raises an admin alert and email', async () => {
  const { user, secret } = await seedUser(app.ctx, 'alerts@example.com', 'preparer');
  await login(new Client(app.baseUrl), user.email, secret);
  const alerts = await app.ctx.db.all<{ message: string }>('SELECT * FROM admin_alerts WHERE user_id = ?', user.id);
  assert.equal(alerts.length, 1);
  assert.match(alerts[0].message, /new device/);
  const c = new Client(app.baseUrl);
  await login(c, user.email, secret);
  const deviceCookie = c.cookies.get('tx_device')!;
  await c.post('/logout');
  const again = new Client(app.baseUrl);
  again.cookies.set('tx_device', deviceCookie);
  await login(again, user.email, secret);
  assert.equal(await app.ctx.db.scalar('SELECT COUNT(*) FROM admin_alerts WHERE user_id = ?', user.id), 2);
  assert.ok((await app.ctx.db.scalar<number>("SELECT COUNT(*) FROM email_outbox WHERE subject LIKE '%Security alert%'")) >= 1);
});

test('admin can revoke one user instantly; their live session dies and login is refused', async () => {
  const admin = await seedUser(app.ctx, 'boss@example.com', 'admin');
  const victim = await seedUser(app.ctx, 'victim@example.com', 'manager');
  const vc = await login(new Client(app.baseUrl), victim.user.email, victim.secret);
  assert.equal((await vc.get('/clients')).status, 200);
  const ac = await login(new Client(app.baseUrl), admin.user.email, admin.secret);
  await ac.get(`/admin/users/${victim.user.id}`);
  assert.equal((await ac.post(`/admin/users/${victim.user.id}`, { _action: 'revoke' })).status, 302);
  const dead = await vc.get('/clients');
  assert.equal(dead.status, 302);
  assert.match(dead.location!, /^\/login/);
  const relogin = await new Client(app.baseUrl).post('/login', { email: victim.user.email, password: PASSWORD });
  assert.equal(relogin.status, 401);
  assert.match(relogin.text, /deactivated/);
  assert.equal((await ac.get('/admin/users')).status, 200);
  const log = await ac.get('/admin/audit?filter=auth');
  assert.match(log.text, /auth\.login_failed/);
  assert.match(log.text, /auth\.login</);
});

test('account locks after repeated failed passwords', async () => {
  const { user } = await seedUser(app.ctx, 'lock@example.com', 'intake');
  const c = new Client(app.baseUrl);
  for (let i = 0; i < 5; i++) await c.post('/login', { email: user.email, password: 'wrong-wrong-wrong-1' });
  const r = await c.post('/login', { email: user.email, password: PASSWORD });
  assert.equal(r.status, 401);
  assert.match(r.text, /temporarily locked/);
  const row = await app.ctx.db.one<{ locked_until: string }>('SELECT locked_until FROM users WHERE id = ?', user.id);
  assert.ok(row!.locked_until && new Date(row!.locked_until) > new Date(), 'lockout is persisted in the database');
});

test('CSRF token is required on state-changing requests', async () => {
  const { user, secret } = await seedUser(app.ctx, 'csrf@example.com', 'admin');
  const c = await login(new Client(app.baseUrl), user.email, secret);
  assert.equal((await c.post('/clients', { legal_name: 'Forged' }, { csrf: 'bogus' })).status, 403);
  assert.equal(await app.ctx.db.scalar("SELECT COUNT(*) FROM clients WHERE legal_name = 'Forged'"), 0);
});

test('production config refuses insecure cookies and requires Supabase settings', async () => {
  const { loadConfig } = await import('../src/config.js');
  const prev = { ...process.env };
  process.env.NODE_ENV = 'production';
  process.env.COOKIE_SECURE = 'false';
  delete process.env.VERCEL;
  process.env.APP_ENCRYPTION_KEY = Buffer.alloc(32, 1).toString('base64');
  process.env.SESSION_SECRET = Buffer.alloc(32, 2).toString('base64');
  process.env.DATABASE_URL = 'postgres://x';
  process.env.SUPABASE_URL = 'https://x.supabase.co';
  process.env.SUPABASE_SERVICE_ROLE_KEY = 'k';
  assert.throws(() => loadConfig(), /COOKIE_SECURE/);
  process.env.COOKIE_SECURE = 'true';
  delete process.env.SUPABASE_SERVICE_ROLE_KEY;
  assert.throws(() => loadConfig(), /SUPABASE_SERVICE_ROLE_KEY/);
  process.env.SUPABASE_SERVICE_ROLE_KEY = 'k';
  delete process.env.DATABASE_URL;
  assert.throws(() => loadConfig(), /DATABASE_URL/);
  // On Vercel, Secure cookies default on even when COOKIE_SECURE is unset.
  process.env.DATABASE_URL = 'postgres://x';
  delete process.env.COOKIE_SECURE;
  process.env.VERCEL = '1';
  assert.equal(loadConfig().cookieSecure, true);
  process.env = prev;
});
