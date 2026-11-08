import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestApp, Client, seedUser, totpCode, type TestApp } from './helpers.js';

const TOKEN = 'bootstrap-test-token-7f3a';

test('bootstrap is a 404 everywhere when BOOTSTRAP_TOKEN is not configured, even with no users', async () => {
  const app = await startTestApp();
  try {
    const c = new Client(app.baseUrl);
    assert.equal((await c.get('/setup')).status, 404);
    assert.equal((await c.post('/setup/token', { token: 'anything' })).status, 404);
    assert.equal((await c.get('/setup/admin')).status, 404);
    assert.equal(await app.ctx.db.scalar('SELECT COUNT(*) FROM users'), 0);
  } finally {
    await app.close();
  }
});

test('bootstrap flow: wrong token → 404 + audit; right token → create admin → forced TOTP enrollment → backup codes; then permanently closed', async () => {
  const app = await startTestApp({ bootstrapToken: TOKEN });
  try {
    const c = new Client(app.baseUrl);
    const page = await c.get('/setup');
    assert.equal(page.status, 200);
    assert.match(page.text, /Bootstrap token/);
    // Admin form is locked until the token is accepted.
    assert.equal((await c.get('/setup/admin')).location, '/setup');

    const wrong = await c.post('/setup/token', { token: 'nope' });
    assert.equal(wrong.status, 404);
    assert.equal(await app.ctx.db.scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'setup.token_rejected'"), 1);
    assert.equal(c.cookies.has('tx_setup'), false);

    const right = await c.post('/setup/token', { token: TOKEN });
    assert.equal(right.status, 302);
    assert.equal(right.location, '/setup/admin');
    assert.ok(c.cookies.has('tx_setup'));
    const form = await c.get('/setup/admin');
    assert.equal(form.status, 200);
    const unlock = form.text.match(/name="_setup" value="([^"]+)"/)![1];

    // Weak password and mismatched confirmation are rejected; no user is created.
    const weak = await c.post('/setup/admin', { _setup: unlock, name: 'Owner', email: 'owner@firm.com', password: 'short1', confirm: 'short1' });
    assert.equal(weak.status, 400);
    assert.match(weak.text, /at least 12 characters/);
    const mismatch = await c.post('/setup/admin', { _setup: unlock, name: 'Owner', email: 'owner@firm.com', password: 'correct-horse-battery-1', confirm: 'correct-horse-battery-2' });
    assert.equal(mismatch.status, 400);
    // A forged form field that does not match the cookie is bounced.
    assert.equal((await c.post('/setup/admin', { _setup: 'forged', name: 'Owner', email: 'owner@firm.com', password: 'correct-horse-battery-1', confirm: 'correct-horse-battery-1' })).location, '/setup');
    assert.equal(await app.ctx.db.scalar('SELECT COUNT(*) FROM users'), 0);

    const created = await c.post('/setup/admin', { _setup: unlock, name: 'Owner One', email: 'owner@firm.com', password: 'correct-horse-battery-1', confirm: 'correct-horse-battery-1' });
    assert.equal(created.status, 302, created.text.slice(0, 300));
    assert.equal(created.location, '/mfa');
    const user = await app.ctx.db.one<any>('SELECT * FROM users');
    assert.equal(user.email, 'owner@firm.com');
    assert.equal(user.role, 'admin');
    assert.equal(user.mfa_enabled, false);
    assert.equal(await app.ctx.db.scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'setup.admin_created' AND entity_id = ?", user.id), 1);
    assert.equal(c.cookies.has('tx_setup'), false, 'unlock cookie is cleared');

    // Nothing but MFA enrollment is reachable with the bootstrap session.
    assert.equal((await c.get('/clients')).location, '/mfa');
    const enroll = await c.get('/mfa');
    assert.equal(enroll.status, 200);
    assert.match(enroll.text, /Set up two-factor authentication/);
    assert.match(enroll.text, /<img src="data:image\/png;base64,/, 'QR code is shown');
    const secret = enroll.text.match(/class="mono">([A-Z2-7]+)</)![1];
    assert.ok(secret.length >= 32, 'manual key is shown');
    const codesPage = await c.post('/mfa/setup', { code: totpCode(secret) });
    assert.equal(codesPage.status, 200);
    const codes = [...codesPage.text.matchAll(/<li>([a-z0-9]{8})<\/li>/g)].map((m) => m[1]);
    assert.equal(codes.length, 8, 'one-time backup codes are displayed');
    const home = await c.get('/');
    assert.equal(home.status, 200);
    assert.match(home.text, /Welcome, Owner One/);
    assert.equal((await c.get('/admin/users')).status, 200);

    // The moment one user exists, every setup route is a 404 — even with the right token or a valid unlock.
    const again = new Client(app.baseUrl);
    assert.equal((await again.get('/setup')).status, 404);
    assert.equal((await again.post('/setup/token', { token: TOKEN })).status, 404);
    assert.equal((await again.get('/setup/admin')).status, 404);
    const c2 = new Client(app.baseUrl);
    c2.cookies.set('tx_setup', unlock);
    assert.equal((await c2.post('/setup/admin', { _setup: unlock, name: 'Intruder', email: 'x@y.com', password: 'correct-horse-battery-1', confirm: 'correct-horse-battery-1' })).status, 404);
    assert.equal(await app.ctx.db.scalar('SELECT COUNT(*) FROM users'), 1);

    // Health reports that bootstrap is finished and the token should be removed.
    const health = await (await fetch(`${app.baseUrl}/health`)).json();
    assert.equal(health.bootstrap.tokenConfigured, true);
    assert.equal(health.bootstrap.setupOpen, false);
    assert.match(health.bootstrap.note, /remove BOOTSTRAP_TOKEN/);
  } finally {
    await app.close();
  }
});

test('bootstrap token guessing is rate limited', async () => {
  const app = await startTestApp({ bootstrapToken: TOKEN });
  try {
    const c = new Client(app.baseUrl);
    let last = 0;
    for (let i = 0; i < 10; i++) last = (await c.post('/setup/token', { token: `guess-${i}` })).status;
    assert.equal(last, 404);
    assert.equal((await c.post('/setup/token', { token: TOKEN })).status, 429, 'even the right token is refused once the limit is hit');
    assert.equal(await app.ctx.db.scalar('SELECT COUNT(*) FROM users'), 0);
  } finally {
    await app.close();
  }
});

test('setup is closed when a user already exists, regardless of how it was created', async () => {
  const app = await startTestApp({ bootstrapToken: TOKEN });
  try {
    await seedUser(app.ctx, 'existing@example.com', 'manager');
    const c = new Client(app.baseUrl);
    assert.equal((await c.get('/setup')).status, 404);
    assert.equal((await c.post('/setup/token', { token: TOKEN })).status, 404);
  } finally {
    await app.close();
  }
});

test('/health reports database and storage reachability without exposing secrets', async () => {
  const app = await startTestApp({ bootstrapToken: TOKEN });
  try {
    const res = await fetch(`${app.baseUrl}/health`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'ok');
    assert.equal(body.checks.database.ok, true);
    assert.equal(body.checks.database.migrationsApplied >= 2, true);
    assert.equal(body.checks.database.usersExist, false);
    assert.equal(body.checks.storage.ok, true);
    assert.match(body.checks.storage.detail, /private/);
    assert.equal(body.bootstrap.setupOpen, true);
    const text = JSON.stringify(body);
    assert.ok(!text.includes(app.storageServer.serviceKey));
    assert.ok(!text.includes(app.config.databaseUrl));
    assert.ok(!text.includes(app.config.encryptionKey.toString('base64')));
    assert.ok(!text.includes(TOKEN));

    // Storage down → degraded with a category, not a stack trace or URL.
    await app.storageServer.stop();
    const down = await fetch(`${app.baseUrl}/health`);
    assert.equal(down.status, 503);
    const d = await down.json();
    assert.equal(d.status, 'degraded');
    assert.equal(d.checks.storage.ok, false);
    assert.match(d.checks.storage.detail, /unreachable/);
    assert.ok(!JSON.stringify(d).includes(app.storageServer.url));
    await app.storageServer.start(); // so close() can stop it cleanly
  } finally {
    await app.close();
  }
});
