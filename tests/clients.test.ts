import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestApp, Client, seedUser, login, type TestApp } from './helpers.js';
import { createClient, getClient, upsertYearHistory, yearsAsClient } from '../src/services/clients.js';

let app: TestApp;
let admin: ReturnType<typeof seedUser>;
let manager: ReturnType<typeof seedUser>;
let preparerA: ReturnType<typeof seedUser>;
let preparerB: ReturnType<typeof seedUser>;
let intake: ReturnType<typeof seedUser>;
let bookkeeper: ReturnType<typeof seedUser>;
before(async () => {
  app = await startTestApp();
  admin = seedUser(app.ctx, 'admin@example.com', 'admin');
  manager = seedUser(app.ctx, 'manager@example.com', 'manager');
  preparerA = seedUser(app.ctx, 'prepa@example.com', 'preparer');
  preparerB = seedUser(app.ctx, 'prepb@example.com', 'preparer');
  intake = seedUser(app.ctx, 'intake@example.com', 'intake');
  bookkeeper = seedUser(app.ctx, 'books@example.com', 'bookkeeper');
});
after(async () => app.close());

const sys = { type: 'system' as const, label: 'test' };

test('SSN is encrypted at rest, masked for staff, revealed only by admin with an audit entry', async () => {
  const c = await login(new Client(app.baseUrl), admin.user.email, admin.secret);
  await c.get('/clients/new');
  const r = await c.post('/clients', { legal_name: 'Jane Taxpayer', ssn: '123-45-6789', dob: '1980-02-03', tags: ['Crypto', 'Real Estate'], assigned_preparer_id: preparerA.user.id, source: 'Referral', notes: 'VIP' });
  assert.equal(r.status, 302);
  const id = r.location!.split('/').pop()!;
  const row = getClient(app.ctx, id)!;
  assert.equal(row.ssn_last4, '6789');
  assert.ok(!row.ssn_enc!.includes('6789') && !row.ssn_enc!.includes('123456789'), 'ciphertext must not contain the SSN');
  assert.match(row.ssn_enc!, /^v1:/);

  const page = await c.get(`/clients/${id}`);
  assert.match(page.text, /\*\*\*-\*\*-6789/);
  assert.doesNotMatch(page.text, /123-45-6789/);
  assert.match(page.text, /Crypto/);

  // Admin reveals: full SSN returned and the reveal is audited.
  const reveal = await c.postJson(`/clients/${id}/ssn/reveal`, { which: 'client' });
  assert.equal(reveal.status, 200);
  assert.equal(JSON.parse(reveal.text).ssn, '123-45-6789');
  const audit = app.ctx.db.prepare("SELECT * FROM audit_log WHERE action = 'client.ssn_reveal' AND client_id = ?").all(id) as any[];
  assert.equal(audit.length, 1);
  assert.equal(audit[0].actor_id, admin.user.id);

  // Manager cannot reveal.
  const m = await login(new Client(app.baseUrl), manager.user.email, manager.secret);
  await m.get(`/clients/${id}`);
  assert.equal((await m.postJson(`/clients/${id}/ssn/reveal`, { which: 'client' })).status, 403);
  const mpage = await m.get(`/clients/${id}`);
  assert.match(mpage.text, /\*\*\*-\*\*-6789/);
  assert.doesNotMatch(mpage.text, /data-reveal-ssn/);

  // Intake staff see no digits, no notes.
  const i = await login(new Client(app.baseUrl), intake.user.email, intake.secret);
  const ipage = await i.get(`/clients/${id}`);
  assert.equal(ipage.status, 200);
  assert.match(ipage.text, /\*\*\*-\*\*-\*\*\*\*/);
  assert.doesNotMatch(ipage.text, /6789/);
  assert.doesNotMatch(ipage.text, /VIP/);
  assert.doesNotMatch(ipage.text, /1980-02-03/);
  assert.equal((await i.postJson(`/clients/${id}/ssn/reveal`, { which: 'client' })).status, 403);
});

test('preparers only see their assigned clients; bookkeeper sees no clients', async () => {
  const mine = createClient(app.ctx, { legal_name: 'Assigned To A', assigned_preparer_id: preparerA.user.id }, sys);
  const other = createClient(app.ctx, { legal_name: 'Assigned To B', assigned_preparer_id: preparerB.user.id }, sys);
  const a = await login(new Client(app.baseUrl), preparerA.user.email, preparerA.secret);
  const list = await a.get('/clients');
  assert.match(list.text, /Assigned To A/);
  assert.doesNotMatch(list.text, /Assigned To B/);
  assert.equal((await a.get(`/clients/${mine.id}`)).status, 200);
  assert.equal((await a.get(`/clients/${other.id}`)).status, 404);
  assert.equal((await a.get(`/clients/${other.id}/edit`)).status, 404);
  assert.equal((await a.post(`/clients/${other.id}`, { legal_name: 'Hijacked' })).status, 404);
  assert.equal((await a.get('/clients/new')).status, 403);
  assert.equal((await a.get('/imports')).status, 403);
  assert.equal((await a.get('/admin')).status, 403);
  const b = await login(new Client(app.baseUrl), bookkeeper.user.email, bookkeeper.secret);
  assert.equal((await b.get('/clients')).status, 403);
  assert.equal((await b.get(`/clients/${mine.id}`)).status, 403);
});

test('edits are audited with changed fields; years as client derives from earliest history', async () => {
  const c = await login(new Client(app.baseUrl), manager.user.email, manager.secret);
  const client = createClient(app.ctx, { legal_name: 'Edit Me', phone: '111' }, sys);
  await c.get(`/clients/${client.id}/edit`);
  const r = await c.post(`/clients/${client.id}`, { legal_name: 'Edit Me', phone: '222', email: 'new@x.com', tags: ['Construction'] });
  assert.equal(r.status, 302);
  const audit = app.ctx.db.prepare("SELECT details FROM audit_log WHERE action = 'client.update' AND client_id = ? ORDER BY id DESC").get(client.id) as any;
  const details = JSON.parse(audit.details);
  assert.deepEqual(details.changed.phone, { from: '111', to: '222' });
  assert.deepEqual(details.changed.tags, { from: [], to: ['Construction'] });
  assert.equal(details.changed.legal_name, undefined);

  const thisYear = new Date().getFullYear();
  assert.equal(yearsAsClient(getClient(app.ctx, client.id)!), 0);
  await c.post(`/clients/${client.id}/history`, { year: String(thisYear - 4), services: '1040', fee: '350.00' });
  const after = getClient(app.ctx, client.id)!;
  assert.equal(after.client_since_year, thisYear - 4);
  assert.equal(yearsAsClient(after), 4);
  upsertYearHistory(app.ctx, client.id, { year: thisYear - 7, services: 'Old' }, sys);
  assert.equal(yearsAsClient(getClient(app.ctx, client.id)!), 7);
  const page = await c.get(`/clients/${client.id}`);
  assert.match(page.text, /350\.00/);
});

test('dependents get encrypted SSNs and are listed on the record', async () => {
  const c = await login(new Client(app.baseUrl), admin.user.email, admin.secret);
  const client = createClient(app.ctx, { legal_name: 'Parent' }, sys);
  await c.get(`/clients/${client.id}`);
  const r = await c.post(`/clients/${client.id}/dependents`, { name: 'Kid One', relationship: 'Daughter', dob: '2015-05-05', ssn: '987654321' });
  assert.equal(r.status, 302);
  const dep = app.ctx.db.prepare('SELECT * FROM dependents WHERE client_id = ?').get(client.id) as any;
  assert.equal(dep.ssn_last4, '4321');
  assert.ok(!dep.ssn_enc.includes('4321'));
  const page = await c.get(`/clients/${client.id}`);
  assert.match(page.text, /Kid One/);
  assert.match(page.text, /\*\*\*-\*\*-4321/);
});

test('invalid SSN is rejected', async () => {
  const c = await login(new Client(app.baseUrl), admin.user.email, admin.secret);
  await c.get('/clients/new');
  const r = await c.post('/clients', { legal_name: 'Bad SSN', ssn: '12345' });
  assert.equal(r.status, 400);
  assert.match(r.text, /SSN must have 9 digits/);
});
