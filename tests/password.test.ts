import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestApp, Client, seedUser, login, totpCode, PASSWORD, FakeSmtpServer, type TestApp } from './helpers.js';
import { validatePasswordStrength } from '../src/services/auth.js';

let smtp: FakeSmtpServer;
let app: TestApp;
before(async () => {
  smtp = await new FakeSmtpServer().start();
  app = await startTestApp({ smtp });
});
after(async () => {
  await app.close();
  await smtp.stop();
});

test('password policy: length, letters+digits, common list, contains email', () => {
  assert.match(validatePasswordStrength('short1', 'a@b.com')!, /12 characters/);
  assert.match(validatePasswordStrength('abcdefghijklmnop', 'a@b.com')!, /letters and numbers/);
  assert.match(validatePasswordStrength('Password1234', 'a@b.com')!, /too common/);
  assert.match(validatePasswordStrength('p@ssw0rd1234', 'a@b.com')!, /too common/);
  assert.match(validatePasswordStrength('maria.lopez99x', 'maria.lopez@firm.com')!, /email/);
  assert.match(validatePasswordStrength('xx maria.lopez@firm.com 1', 'maria.lopez@firm.com')!, /email/);
  assert.equal(validatePasswordStrength('Blue-Giraffe-Sings-42', 'maria.lopez@firm.com'), null);
});

test('change password: wrong current, wrong TOTP, weak, reuse are rejected; success ends other sessions, audits, emails', async () => {
  const { user, secret } = await seedUser(app.ctx, 'changer@example.com', 'manager');
  const me = await login(new Client(app.baseUrl), user.email, secret);
  const other = await login(new Client(app.baseUrl), user.email, secret);
  const sibling = await app.spawnSibling();
  const roaming = new Client(sibling.baseUrl);
  roaming.cookies = new Map(other.cookies);
  assert.equal((await roaming.get('/clients')).status, 200);
  await me.get('/account/password');
  const attempt = (f: Record<string, string>) => me.post('/account/password', { current: PASSWORD, password: 'Blue-Giraffe-Sings-42', confirm: 'Blue-Giraffe-Sings-42', totp: totpCode(secret), ...f });

  let r = await attempt({ current: 'wrong-wrong-wrong-1' });
  assert.equal(r.status, 400);
  assert.match(r.text, /Current password is incorrect/);
  r = await attempt({ totp: '000000' });
  assert.equal(r.status, 400);
  assert.match(r.text, /authenticator code is not valid/);
  r = await attempt({ password: 'password1234', confirm: 'password1234' });
  assert.equal(r.status, 400);
  assert.match(r.text, /too common/);
  r = await attempt({ password: 'changer@example.com1', confirm: 'changer@example.com1' });
  assert.equal(r.status, 400);
  assert.match(r.text, /email/);
  r = await attempt({ confirm: 'Blue-Giraffe-Sings-43' });
  assert.equal(r.status, 400);
  assert.match(r.text, /do not match/);
  r = await attempt({ password: PASSWORD, confirm: PASSWORD });
  assert.equal(r.status, 400);
  assert.match(r.text, /not used before/);
  assert.equal(await app.ctx.db.scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'user.password_change_failed' AND actor_id = ?", user.id), 2);
  // Nothing changed; both sessions still live.
  assert.equal(await app.ctx.db.scalar('SELECT COUNT(*) FROM sessions WHERE user_id = ?', user.id), 2);

  r = await attempt({});
  assert.equal(r.status, 302, r.text.slice(0, 200));
  assert.equal(r.location, '/account');
  // Current session kept, the other one (and its cross-instance view) is gone.
  assert.equal((await me.get('/account')).status, 200);
  assert.equal(await app.ctx.db.scalar('SELECT COUNT(*) FROM sessions WHERE user_id = ?', user.id), 1);
  assert.equal((await other.get('/clients')).status, 302);
  assert.equal((await roaming.get('/clients')).status, 302);
  assert.equal(await app.ctx.db.scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'user.password_changed' AND actor_id = ?", user.id), 1);
  const mail = await app.ctx.db.one<any>("SELECT * FROM email_outbox WHERE to_addr = ? AND subject LIKE '%password was changed%'", user.email);
  assert.ok(mail);
  assert.equal(mail.status, 'sent');
  assert.ok(!mail.body.includes('Blue-Giraffe'), 'email never contains the password');
  // Old password no longer works; new one does.
  assert.equal((await new Client(app.baseUrl).post('/login', { email: user.email, password: PASSWORD })).status, 401);
  assert.equal((await new Client(app.baseUrl).post('/login', { email: user.email, password: 'Blue-Giraffe-Sings-42' })).status, 302);
});

test('admin-created users and admin password resets force a password change at first login', async () => {
  const admin = await seedUser(app.ctx, 'admin@example.com', 'admin');
  const ac = await login(new Client(app.baseUrl), admin.user.email, admin.secret);
  await ac.get('/admin/users/new');
  const created = await ac.post('/admin/users', { name: 'Temp User', email: 'temp@example.com', role: 'intake', password: 'Starter-Key-2026-ok' });
  assert.equal(created.status, 302, created.text.slice(0, 300));
  const u = await app.ctx.db.one<any>("SELECT * FROM users WHERE email = 'temp@example.com'");
  assert.equal(u.must_change_password, true);

  // First login: password -> MFA enrollment -> then forced to the change screen before anything else.
  const c = new Client(app.baseUrl);
  await c.post('/login', { email: 'temp@example.com', password: 'Starter-Key-2026-ok' });
  const setup = await c.get('/mfa');
  const secret = setup.text.match(/class="mono">([A-Z2-7]+)</)![1];
  await c.post('/mfa/setup', { code: totpCode(secret) });
  const home = await c.get('/');
  assert.equal(home.status, 302);
  assert.equal(home.location, '/account/password');
  assert.equal((await c.get('/clients')).location, '/account/password');
  assert.equal((await c.postJson('/clients/00000000-0000-0000-0000-000000000000/ssn/reveal', {})).status, 403);
  const page = await c.get('/account/password');
  assert.equal(page.status, 200);
  assert.match(page.text, /temporary password/);
  const changed = await c.post('/account/password', { current: 'Starter-Key-2026-ok', password: 'Quiet-River-Stone-77', confirm: 'Quiet-River-Stone-77', totp: totpCode(secret) });
  assert.equal(changed.status, 302);
  assert.equal((await c.get('/clients')).status, 200);
  assert.equal((await app.ctx.db.one<any>("SELECT must_change_password FROM users WHERE email = 'temp@example.com'")).must_change_password, false);

  // Admin reset: flag set again, sessions ended, forced at next login.
  await ac.get(`/admin/users/${u.id}`);
  assert.equal((await ac.post(`/admin/users/${u.id}`, { _action: 'reset_password', password: 'Reset-Pass-Again-99' })).status, 302);
  assert.equal((await c.get('/clients')).status, 302);
  assert.equal((await app.ctx.db.one<any>('SELECT must_change_password FROM users WHERE id = ?', u.id)).must_change_password, true);
  const c2 = new Client(app.baseUrl);
  await c2.post('/login', { email: 'temp@example.com', password: 'Reset-Pass-Again-99' });
  await c2.get('/mfa');
  await c2.post('/mfa', { code: totpCode(secret) });
  assert.equal((await c2.get('/')).location, '/account/password');
});

test('sign out of all devices keeps only the current session', async () => {
  const { user, secret } = await seedUser(app.ctx, 'devices@example.com', 'preparer');
  const me = await login(new Client(app.baseUrl), user.email, secret);
  const other1 = await login(new Client(app.baseUrl), user.email, secret);
  const other2 = await login(new Client(app.baseUrl), user.email, secret);
  assert.equal(await app.ctx.db.scalar('SELECT COUNT(*) FROM sessions WHERE user_id = ?', user.id), 3);
  await me.get('/account');
  const r = await me.post('/account/sessions/revoke-others');
  assert.equal(r.status, 302);
  assert.equal((await me.get('/account')).status, 200);
  assert.equal((await other1.get('/')).status, 302);
  assert.equal((await other2.get('/')).status, 302);
  assert.equal(await app.ctx.db.scalar('SELECT COUNT(*) FROM sessions WHERE user_id = ?', user.id), 1);
  assert.equal(await app.ctx.db.scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'auth.other_sessions_revoked' AND actor_id = ?", user.id), 1);
});
