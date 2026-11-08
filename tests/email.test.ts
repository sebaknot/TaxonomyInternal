import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestApp, Client, seedUser, login, FakeSmtpServer, type TestApp } from './helpers.js';
import { sanitizeSmtpError } from '../src/services/mailer.js';

let smtp: FakeSmtpServer;
let app: TestApp;
let admin: Awaited<ReturnType<typeof seedUser>>;
before(async () => {
  smtp = await new FakeSmtpServer().start();
  app = await startTestApp({ smtp });
  admin = await seedUser(app.ctx, 'admin@example.com', 'admin');
});
after(async () => {
  await app.close();
  await smtp.stop();
});

test('configured: messages are delivered over SMTP with AUTH and recorded as sent', async () => {
  assert.equal(app.ctx.mailer.configured, true);
  const out = await app.ctx.mailer.send('client@example.com', 'Your secure link', 'Hello, here is your link: https://example.test/portal/r/abc');
  assert.equal(out.status, 'sent');
  const row = await app.ctx.db.one<any>('SELECT * FROM email_outbox WHERE id = ?', out.id);
  assert.equal(row.status, 'sent');
  assert.equal(row.attempts, 1);
  assert.equal(row.last_error, null);
  assert.ok(row.sent_at);
  assert.equal(smtp.messages.length, 1);
  assert.equal(smtp.messages[0].authed, true);
  assert.deepEqual(smtp.messages[0].to, ['client@example.com']);
  assert.match(smtp.messages[0].data, /Subject: Your secure link/);
  assert.match(smtp.messages[0].data, /here is your link/);
});

test('failure marks the row failed with a sanitized error, never blocks the caller; Retry delivers and is audited', async () => {
  smtp.mode = 'reject';
  const out = await app.ctx.mailer.send('bounce@example.com', 'Alert', 'body');
  assert.equal(out.status, 'failed');
  assert.match(out.error!, /550/);
  let row = await app.ctx.db.one<any>('SELECT * FROM email_outbox WHERE id = ?', out.id);
  assert.equal(row.status, 'failed');
  assert.equal(row.attempts, 1);
  assert.match(row.last_error, /recipient rejected/);
  assert.ok(!row.last_error.includes(smtp.pass));

  // A user action that sends email still succeeds when SMTP fails (magic link email).
  const c = await login(new Client(app.baseUrl), admin.user.email, admin.secret);
  const { createClient } = await import('../src/services/clients.js');
  const { createMagicLink } = await import('../src/services/magic.js');
  const client = await createClient(app.ctx, { legal_name: 'Mail Client', email: 'mail@example.com', ssn: '111-11-1111', dob: '1980-01-01' }, { type: 'system', label: 'test' });
  const { link } = await createMagicLink(app.ctx, { type: 'returning', clientId: client.id, taxYear: 2025 }, { id: admin.user.id, email: admin.user.email, name: 'A', role: 'admin' });
  await c.get(`/clients/${client.id}`);
  const r = await c.post(`/clients/${client.id}/magic-links/${link.id}/email`);
  assert.equal(r.status, 302, 'user action completes even though delivery failed');
  const failedLink = await app.ctx.db.one<any>("SELECT * FROM email_outbox WHERE to_addr = 'mail@example.com' ORDER BY ts DESC");
  assert.equal(failedLink.status, 'failed');
  // The magic link email never contains the SSN or DOB.
  assert.ok(!failedLink.body.includes('1111') && !failedLink.body.includes('1980-01-01'));

  // Outbox page shows the status and a Retry button; retry succeeds once SMTP recovers.
  const page = await c.get('/admin/outbox');
  assert.match(page.text, /failed/);
  assert.match(page.text, new RegExp(`/admin/outbox/${out.id}/retry`));
  smtp.mode = 'ok';
  const retry = await c.post(`/admin/outbox/${out.id}/retry`);
  assert.equal(retry.status, 302);
  row = await app.ctx.db.one<any>('SELECT * FROM email_outbox WHERE id = ?', out.id);
  assert.equal(row.status, 'sent');
  assert.equal(row.attempts, 2);
  assert.equal(row.last_error, null);
  assert.equal(await app.ctx.db.scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'email.retry' AND entity_id = ?", out.id), 1);
  // Non-admins cannot retry.
  const mgr = await seedUser(app.ctx, 'mgr@example.com', 'manager');
  const m = await login(new Client(app.baseUrl), mgr.user.email, mgr.secret);
  assert.equal((await m.post(`/admin/outbox/${out.id}/retry`)).status, 403);
});

test('a dropped connection is recorded as failed without hanging the request', async () => {
  smtp.mode = 'drop';
  const t0 = Date.now();
  const out = await app.ctx.mailer.send('x@example.com', 's', 'b');
  assert.equal(out.status, 'failed');
  assert.ok(Date.now() - t0 < 9_000);
  smtp.mode = 'ok';
});

test('Admin → Settings test email reports success and the exact SMTP error', async () => {
  const c = await login(new Client(app.baseUrl), admin.user.email, admin.secret);
  await c.get('/admin/settings');
  assert.equal((await c.post('/admin/settings/test-email', { to: 'me@example.com' })).status, 302);
  const ok = await c.get('/admin/settings');
  assert.match(ok.text, /Test email sent to me@example.com/);
  assert.ok(smtp.messages.some((m) => m.to.includes('me@example.com') && /Test email/.test(m.data)));
  smtp.mode = 'reject';
  await c.post('/admin/settings/test-email', { to: 'me@example.com' });
  const bad = await c.get('/admin/settings');
  assert.match(bad.text, /Test email failed: .*550/);
  smtp.mode = 'ok';
  assert.equal(await app.ctx.db.scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'email.test'"), 2);
  // Health reports configuration state only.
  const health = await (await fetch(`${app.baseUrl}/health`)).json();
  assert.equal(health.config.smtpConfigured, true);
  assert.ok(!JSON.stringify(health).includes(smtp.pass) && !JSON.stringify(health).includes(smtp.user));
});

test('errors are sanitized of credentials', () => {
  const cfg = { host: 'h', port: 25, secure: false, user: 'bob@corp.com', pass: 'hunter2hunter2', from: 'x' };
  const msg = sanitizeSmtpError(new Error('Invalid login: 535 bad creds for bob@corp.com using hunter2hunter2 AUTH PLAIN AGJvYgBodW50ZXIy'), cfg);
  assert.ok(!msg.includes('hunter2hunter2'));
  assert.ok(!msg.includes('bob@corp.com'));
  assert.ok(!msg.includes('AGJvYgBodW50ZXIy'));
});

test('not configured: outbox-only behaviour, banner shown, retry/test disabled', async () => {
  const plain = await startTestApp();
  try {
    assert.equal(plain.ctx.mailer.configured, false);
    const out = await plain.ctx.mailer.send('a@example.com', 's', 'b');
    assert.equal(out.status, 'queued');
    const row = await plain.ctx.db.one<any>('SELECT * FROM email_outbox WHERE id = ?', out.id);
    assert.equal(row.status, 'queued');
    assert.equal(row.attempts, 0);
    const a = await seedUser(plain.ctx, 'admin2@example.com', 'admin');
    const c = await login(new Client(plain.baseUrl), a.user.email, a.secret);
    const page = await c.get('/admin');
    assert.match(page.text, /Email is not configured — messages are not being delivered/);
    const retry = await plain.ctx.mailer.retry(out.id);
    assert.equal(retry.status, 'queued');
    const test = await plain.ctx.mailer.sendTest('a@example.com');
    assert.equal(test.ok, false);
    assert.match(test.error!, /not configured/);
    const health = await (await fetch(`${plain.baseUrl}/health`)).json();
    assert.equal(health.config.smtpConfigured, false);
  } finally {
    await plain.close();
  }
});
