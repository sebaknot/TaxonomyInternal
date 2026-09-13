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
  const { user, secret } = seedUser(app.ctx, 'mfa@example.com', 'admin');
  const c = new Client(app.baseUrl);
  const bad = await c.post('/login', { email: user.email, password: 'nope-nope-nope-1' });
  assert.equal(bad.status, 401);
  const failed = app.ctx.db.prepare("SELECT COUNT(*) c FROM audit_log WHERE action = 'auth.login_failed' AND actor_id = ?").get(user.id) as any;
  assert.equal(failed.c, 1);

  const ok = await c.post('/login', { email: user.email, password: PASSWORD });
  assert.equal(ok.status, 302);
  assert.match(ok.location!, /^\/mfa/);
  // Password-only session cannot reach the app.
  const blocked = await c.get('/clients');
  assert.equal(blocked.status, 302);
  assert.equal(blocked.location, '/mfa');
  // Wrong TOTP code rejected.
  await c.get('/mfa');
  const badCode = await c.post('/mfa', { code: '000000' });
  assert.equal(badCode.status, 401);
  // Correct code passes and a login is audited.
  const good = await c.post('/mfa', { code: totpCode(secret) });
  assert.equal(good.status, 302);
  const home = await c.get('/');
  assert.equal(home.status, 200);
  assert.match(home.text, /Welcome, mfa/);
  const logins = app.ctx.db.prepare("SELECT COUNT(*) c FROM audit_log WHERE action = 'auth.login' AND actor_id = ?").get(user.id) as any;
  assert.equal(logins.c, 1);
});

test('a new user must enroll MFA before reaching anything; backup codes work once', async () => {
  const { createUser } = await import('../src/services/auth.js');
  const u = createUser(app.ctx, { email: 'fresh@example.com', name: 'Fresh', role: 'manager', password: PASSWORD }, null);
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

  // Sign out, sign back in with a backup code; the same code can't be reused.
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
  const { user, secret } = seedUser(app.ctx, 'idle@example.com', 'admin');
  const c = await login(new Client(app.baseUrl), user.email, secret);
  assert.equal((await c.get('/')).status, 200);
  // Simulate 16 minutes of inactivity with the default 15-minute timeout.
  app.ctx.db.prepare("UPDATE sessions SET last_activity_at = datetime('now', '-16 minutes') WHERE user_id = ?").run(user.id);
  const r = await c.get('/clients');
  assert.equal(r.status, 302);
  assert.match(r.location!, /^\/login/);
  const logout = app.ctx.db.prepare("SELECT details FROM audit_log WHERE action = 'auth.logout' AND actor_id = ? ORDER BY id DESC").get(user.id) as any;
  assert.match(logout.details, /idle_timeout/);

  // Admin raises the timeout to 60 minutes: 16 idle minutes is now fine.
  const c2 = await login(new Client(app.baseUrl), user.email, secret);
  await c2.get('/admin/settings');
  const save = await c2.post('/admin/settings', { session_idle_minutes: '60', magic_link_valid_hours: '72', current_tax_year: '2025', firm_name: 'Taxonomy' });
  assert.equal(save.status, 302);
  app.ctx.db.prepare("UPDATE sessions SET last_activity_at = datetime('now', '-16 minutes') WHERE user_id = ?").run(user.id);
  assert.equal((await c2.get('/clients')).status, 200);
  setSetting(app.ctx, 'session_idle_minutes', '15');
});

test('login from a new device / location raises an admin alert and email', async () => {
  const { user, secret } = seedUser(app.ctx, 'alerts@example.com', 'preparer');
  await login(new Client(app.baseUrl), user.email, secret);
  const alerts = app.ctx.db.prepare("SELECT * FROM admin_alerts WHERE user_id = ?").all(user.id) as any[];
  assert.equal(alerts.length, 1);
  assert.match(alerts[0].message, /new device/);
  // Same browser (device cookie) again: no new alert.
  const c = new Client(app.baseUrl);
  await login(c, user.email, secret);
  const deviceCookie = c.cookies.get('tx_device')!;
  await c.post('/logout');
  const again = new Client(app.baseUrl);
  again.cookies.set('tx_device', deviceCookie);
  await login(again, user.email, secret);
  const after = app.ctx.db.prepare("SELECT COUNT(*) c FROM admin_alerts WHERE user_id = ?").get(user.id) as any;
  assert.equal(after.c, 2); // first login + second (new device); third reused the device
  const mail = app.ctx.db.prepare("SELECT COUNT(*) c FROM email_outbox WHERE subject LIKE '%Security alert%'").get() as any;
  assert.ok(mail.c >= 1);
});

test('admin can revoke one user instantly; their live session dies and login is refused', async () => {
  const admin = seedUser(app.ctx, 'boss@example.com', 'admin');
  const victim = seedUser(app.ctx, 'victim@example.com', 'manager');
  const vc = await login(new Client(app.baseUrl), victim.user.email, victim.secret);
  assert.equal((await vc.get('/clients')).status, 200);
  const ac = await login(new Client(app.baseUrl), admin.user.email, admin.secret);
  await ac.get(`/admin/users/${victim.user.id}`);
  const r = await ac.post(`/admin/users/${victim.user.id}`, { _action: 'revoke' });
  assert.equal(r.status, 302);
  const dead = await vc.get('/clients');
  assert.equal(dead.status, 302);
  assert.match(dead.location!, /^\/login/);
  const relogin = await new Client(app.baseUrl).post('/login', { email: victim.user.email, password: PASSWORD });
  assert.equal(relogin.status, 401);
  assert.match(relogin.text, /deactivated/);
  // Admin's own session is untouched.
  assert.equal((await ac.get('/admin/users')).status, 200);
  // Audit log shows logins, logouts and failures for admin.
  const log = await ac.get('/admin/audit?filter=auth');
  assert.match(log.text, /auth\.login_failed/);
  assert.match(log.text, /auth\.login</);
});

test('account locks after repeated failed passwords', async () => {
  const { user } = seedUser(app.ctx, 'lock@example.com', 'intake');
  const c = new Client(app.baseUrl);
  for (let i = 0; i < 5; i++) await c.post('/login', { email: user.email, password: 'wrong-wrong-wrong-1' });
  const r = await c.post('/login', { email: user.email, password: PASSWORD });
  assert.equal(r.status, 401);
  assert.match(r.text, /temporarily locked/);
});

test('CSRF token is required on state-changing requests', async () => {
  const { user, secret } = seedUser(app.ctx, 'csrf@example.com', 'admin');
  const c = await login(new Client(app.baseUrl), user.email, secret);
  const r = await c.post('/clients', { legal_name: 'Forged' }, { csrf: 'bogus' });
  assert.equal(r.status, 403);
  assert.equal((app.ctx.db.prepare("SELECT COUNT(*) c FROM clients WHERE legal_name = 'Forged'").get() as any).c, 0);
});

test('production config refuses insecure cookies', async () => {
  const { loadConfig } = await import('../src/config.js');
  const prev = { ...process.env };
  process.env.NODE_ENV = 'production';
  process.env.COOKIE_SECURE = 'false';
  process.env.APP_ENCRYPTION_KEY = Buffer.alloc(32, 1).toString('base64');
  process.env.SESSION_SECRET = Buffer.alloc(32, 2).toString('base64');
  assert.throws(() => loadConfig(), /COOKIE_SECURE/);
  process.env = prev;
});
