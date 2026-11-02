import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestApp, Client, seedUser, login, PASSWORD, totpCode, type TestApp } from './helpers.js';
import { createClient } from '../src/services/clients.js';

/**
 * Serverless invocations share nothing but the database. These tests boot a second app instance
 * (a "sibling", equivalent to another Vercel function instance) against the same Postgres and
 * check that sessions, lockouts and rate limits carry over.
 */
let app: TestApp;
let sibling: { baseUrl: string };
before(async () => {
  app = await startTestApp();
  sibling = await app.spawnSibling();
});
after(async () => app.close());
const sys = { type: 'system' as const, label: 'test' };

test('a staff session established on one instance is valid on another, and revocation propagates', async () => {
  const { user, secret } = await seedUser(app.ctx, 'roam@example.com', 'manager');
  const client = await createClient(app.ctx, { legal_name: 'Roaming Client' }, sys);
  const c = await login(new Client(app.baseUrl), user.email, secret);
  const other = new Client(sibling.baseUrl);
  other.cookies = new Map(c.cookies);
  const page = await other.get(`/clients/${client.id}`);
  assert.equal(page.status, 200);
  assert.match(page.text, /Roaming Client/);
  // CSRF token issued by instance A works on instance B (it lives on the session row).
  await other.get(`/clients/${client.id}/edit`);
  assert.equal((await other.post(`/clients/${client.id}`, { legal_name: 'Roaming Client', phone: '777' })).status, 302);
  // Activity on B refreshes the idle timer seen by A.
  const row = await app.ctx.db.one<{ last_activity_at: string }>('SELECT last_activity_at FROM sessions WHERE user_id = ?', user.id);
  assert.ok(Date.now() - new Date(row!.last_activity_at).getTime() < 5000);
  // Logging out on B ends the session for A.
  await other.post('/logout');
  const dead = await c.get('/clients');
  assert.equal(dead.status, 302);
  assert.match(dead.location!, /^\/login/);
  assert.equal(await app.ctx.db.scalar('SELECT COUNT(*) FROM sessions WHERE user_id = ?', user.id), 0);
});

test('the MFA step can be completed on a different instance than the password step', async () => {
  const { user, secret } = await seedUser(app.ctx, 'split@example.com', 'admin');
  const a = new Client(app.baseUrl);
  assert.equal((await a.post('/login', { email: user.email, password: PASSWORD })).status, 302);
  const b = new Client(sibling.baseUrl);
  b.cookies = new Map(a.cookies);
  await b.get('/mfa');
  assert.equal((await b.post('/mfa', { code: totpCode(secret) })).status, 302);
  assert.equal((await a.get('/')).status, 200);
});

test('failed-login lockout counters are shared across instances', async () => {
  const { user } = await seedUser(app.ctx, 'shared-lock@example.com', 'intake');
  const a = new Client(app.baseUrl);
  const b = new Client(sibling.baseUrl);
  for (let i = 0; i < 3; i++) await a.post('/login', { email: user.email, password: 'wrong-wrong-wrong-1' });
  for (let i = 0; i < 2; i++) await b.post('/login', { email: user.email, password: 'wrong-wrong-wrong-1' });
  const r = await b.post('/login', { email: user.email, password: PASSWORD });
  assert.equal(r.status, 401);
  assert.match(r.text, /temporarily locked/);
  assert.equal((await a.post('/login', { email: user.email, password: PASSWORD })).status, 401);
});

test('rate limits live in the database: hitting the limit on one instance blocks the other', async () => {
  // Portal links are limited to 40 hits per 15 minutes per IP.
  const a = new Client(app.baseUrl);
  const b = new Client(sibling.baseUrl);
  let last = 0;
  for (let i = 0; i < 40; i++) last = (await a.get('/portal/r/bogus-token')).status;
  assert.equal(last, 410);
  const blockedOnA = await a.get('/portal/r/bogus-token');
  assert.equal(blockedOnA.status, 429);
  const blockedOnB = await b.get('/portal/r/bogus-token');
  assert.equal(blockedOnB.status, 429);
  const row = await app.ctx.db.one<{ count: number }>("SELECT count FROM rate_limits WHERE key LIKE 'portal:%'");
  assert.ok(row && row.count >= 42);
  // A new window resets the counter.
  await app.ctx.db.run("UPDATE rate_limits SET window_start = now() - interval '16 minutes' WHERE key LIKE 'portal:%'");
  assert.equal((await b.get('/portal/r/bogus-token')).status, 410);
  // Login limiter is separate from the portal limiter.
  assert.notEqual((await a.post('/login', { email: 'nobody@example.com', password: 'x-x-x-x-x-x-x-1' })).status, 429);
});

test('portal sessions and magic-link attempt counters are shared across instances', async () => {
  const { createMagicLink } = await import('../src/services/magic.js');
  const staff = await seedUser(app.ctx, 'portal-staff@example.com', 'manager');
  const client = await createClient(app.ctx, { legal_name: 'Portal Roamer', ssn: '555-55-5555', dob: '1985-05-05' }, sys);
  const { url } = await createMagicLink(app.ctx, { type: 'returning', clientId: client.id, taxYear: 2025 }, { id: staff.user.id, email: staff.user.email, name: 'S', role: 'manager' });
  const a = new Client(app.baseUrl);
  await a.get(`/portal/r/${url.split('/').pop()}`);
  const b = new Client(sibling.baseUrl);
  b.cookies = new Map(a.cookies);
  await b.get('/portal/verify');
  assert.equal((await b.post('/portal/verify', { last4: '0000', dob: '1985-05-05' })).status, 401);
  assert.equal((await b.post('/portal/verify', { last4: '5555', dob: '1985-05-05' })).status, 302);
  const home = await a.get('/portal/home');
  assert.equal(home.status, 200);
  assert.match(home.text, /Portal Roamer/);
  assert.equal(await app.ctx.db.scalar('SELECT verify_attempts FROM magic_links WHERE client_id = ?', client.id), 1);
});

test('expired sessions are purged by the cleanup job', async () => {
  const { user, secret } = await seedUser(app.ctx, 'purge@example.com', 'manager');
  await login(new Client(app.baseUrl), user.email, secret);
  await app.ctx.db.run("UPDATE sessions SET expires_at = now() - interval '1 hour' WHERE user_id = ?", user.id);
  const res = await fetch(`${app.baseUrl}/api/cron/cleanup`, { headers: { authorization: 'Bearer cron-test-secret' } });
  const body = await res.json();
  assert.ok(body.sessions >= 1);
  assert.equal(await app.ctx.db.scalar('SELECT COUNT(*) FROM sessions WHERE user_id = ?', user.id), 0);
});
