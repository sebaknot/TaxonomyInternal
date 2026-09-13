import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestApp, Client, seedUser, login, type TestApp } from './helpers.js';
import { createClient, getClient } from '../src/services/clients.js';
import { createMagicLink } from '../src/services/magic.js';

let app: TestApp;
let staff: ReturnType<typeof seedUser>;
before(async () => {
  app = await startTestApp();
  staff = seedUser(app.ctx, 'staff@example.com', 'manager');
});
after(async () => app.close());
const sys = { type: 'system' as const, label: 'test' };

test('returning client: link → verification gate → confirm/update sections → upload; everything logged on the record', async () => {
  const client = createClient(app.ctx, { legal_name: 'Rita Returning', ssn: '123-45-6789', dob: '1970-01-15', phone: '555-1111', email: 'rita@x.com' }, sys);
  const s = await login(new Client(app.baseUrl), staff.user.email, staff.secret);
  await s.get(`/clients/${client.id}`);
  const gen = await s.post(`/clients/${client.id}/magic-links`, { tax_year: '2025' });
  assert.equal(gen.status, 200);
  const url = gen.text.match(/(http:\/\/[^<\s]+\/portal\/r\/[A-Za-z0-9_-]+)/)![1];
  const token = url.split('/').pop()!;
  // Token is stored hashed only.
  assert.equal((app.ctx.db.prepare('SELECT COUNT(*) c FROM magic_links WHERE token_hash = ?').get(token) as any).c, 0);

  const p = new Client(app.baseUrl);
  const open = await p.get(`/portal/r/${token}`);
  assert.equal(open.status, 302);
  assert.equal(open.location, '/portal/verify');
  // No data before verification.
  assert.equal((await p.get('/portal/home')).status, 302);
  const verify = await p.get('/portal/verify');
  assert.equal(verify.status, 200);
  assert.doesNotMatch(verify.text, /555-1111/);
  const wrong = await p.post('/portal/verify', { last4: '0000', dob: '1970-01-15' });
  assert.equal(wrong.status, 401);
  const right = await p.post('/portal/verify', { last4: '6789', dob: '1970-01-15' });
  assert.equal(right.status, 302);
  const home = await p.get('/portal/home');
  assert.equal(home.status, 200);
  assert.match(home.text, /555-1111/);
  assert.match(home.text, /\*\*\*-\*\*-6789/);
  assert.doesNotMatch(home.text, /123-45-6789/);

  // Confirm "no changes" on contact; update filing status.
  assert.equal((await p.post('/portal/confirm/contact')).status, 302);
  await p.get('/portal/update/filing');
  assert.equal((await p.post('/portal/update/filing', { filing_status: 'Head of Household', spouse_name: '', spouse_dob: '' })).status, 302);
  assert.equal(getClient(app.ctx, client.id)!.filing_status, 'Head of Household');
  // Add a dependent through the portal.
  await p.get('/portal/home');
  assert.equal((await p.post('/portal/dependents', { name: 'Junior', relationship: 'Son', dob: '2012-02-02', ssn: '999-88-7777' })).status, 302);
  // Upload lands under the link's tax year.
  await p.get('/portal/home');
  const up = await p.upload('/portal/documents', { category: 'W-2s', description: 'W-2 from Acme' }, { name: 'w2.pdf', content: 'pdf bytes' });
  assert.equal(up.status, 302);
  const doc = app.ctx.db.prepare('SELECT * FROM documents WHERE client_id = ?').get(client.id) as any;
  assert.equal(doc.tax_year, 2025);
  assert.equal(doc.category, 'W-2s');
  assert.equal(doc.title, 'W-2 from Acme');
  const ver = app.ctx.db.prepare('SELECT * FROM document_versions WHERE document_id = ?').get(doc.id) as any;
  assert.equal(ver.uploaded_by_type, 'client');
  const home2 = await p.get('/portal/home');
  assert.match(home2.text, /confirmed unchanged/);
  assert.match(home2.text, /w2\.pdf/);

  // Staff sees the activity on the client record.
  const actions = (app.ctx.db.prepare("SELECT action FROM audit_log WHERE client_id = ? AND actor_type = 'client' ORDER BY id").all(client.id) as any[]).map((a) => a.action);
  assert.deepEqual(actions, ['portal.verify_failed', 'portal.verified', 'portal.section_confirmed', 'client.update', 'portal.section_updated', 'client.dependent_add', 'portal.section_updated', 'document.upload']);
  const record = await s.get(`/clients/${client.id}`);
  assert.match(record.text, /section confirmed/);
  assert.match(record.text, /Junior/);
  assert.match(record.text, /w2\.pdf/);
  assert.match(record.text, /rita@x\.com.*\(client\)|\(client\)/);

  // Revoking the link kills the portal session.
  const link = app.ctx.db.prepare('SELECT id FROM magic_links WHERE client_id = ?').get(client.id) as any;
  await s.get(`/clients/${client.id}`);
  await s.post(`/clients/${client.id}/magic-links/${link.id}/revoke`);
  assert.equal((await p.get('/portal/home')).status, 401);
});

test('verification locks after 5 failures; expired links are refused', async () => {
  const client = createClient(app.ctx, { legal_name: 'Lock Me', ssn: '111-11-1111', dob: '1980-01-01' }, sys);
  const { url } = createMagicLink(app.ctx, { type: 'returning', clientId: client.id, taxYear: 2025 }, { id: staff.user.id, email: staff.user.email, name: 'S', role: 'manager' });
  const token = url.split('/').pop()!;
  const p = new Client(app.baseUrl);
  await p.get(`/portal/r/${token}`);
  await p.get('/portal/verify');
  let last: any;
  for (let i = 0; i < 5; i++) last = await p.post('/portal/verify', { last4: '9999', dob: '1980-01-01' });
  assert.equal(last.status, 403);
  assert.match(last.text, /Too many unsuccessful/);
  assert.equal((await new Client(app.baseUrl).get(`/portal/r/${token}`)).status, 410);

  const c2 = createClient(app.ctx, { legal_name: 'Expired', ssn: '222-22-2222', dob: '1980-01-01' }, sys);
  const l2 = createMagicLink(app.ctx, { type: 'returning', clientId: c2.id, taxYear: 2025 }, { id: staff.user.id, email: staff.user.email, name: 'S', role: 'manager' });
  app.ctx.db.prepare("UPDATE magic_links SET expires_at = '2000-01-01T00:00:00.000Z' WHERE id = ?").run(l2.link.id);
  const r = await new Client(app.baseUrl).get(`/portal/r/${l2.url.split('/').pop()}`);
  assert.equal(r.status, 410);
  assert.match(r.text, /expired/);
  assert.equal((await new Client(app.baseUrl).get('/portal/r/not-a-real-token')).status, 410);
});

test('new client intake: identity step → full form → record created automatically → can upload', async () => {
  const s = await login(new Client(app.baseUrl), staff.user.email, staff.secret);
  await s.get('/clients/intake-links');
  const gen = await s.post('/clients/intake-links', { tax_year: '2025', label: 'Referred by Ana' });
  assert.equal(gen.status, 200);
  const url = gen.text.match(/(http:\/\/[^<\s]+\/portal\/new\/[A-Za-z0-9_-]+)/)![1];
  const token = url.split('/').pop()!;
  const p = new Client(app.baseUrl);
  const open = await p.get(`/portal/new/${token}`);
  assert.equal(open.location, '/portal/identity');
  // Cannot skip the identity step.
  assert.equal((await p.get('/portal/intake')).location, '/portal/identity');
  await p.get('/portal/identity');
  assert.equal((await p.post('/portal/identity', { name: 'N', email: 'bad', phone: '1' })).status, 400);
  assert.equal((await p.post('/portal/identity', { name: 'Nina New', email: 'nina@x.com', phone: '555-2222' })).location, '/portal/intake');
  const form = await p.get('/portal/intake');
  assert.match(form.text, /Thanks, Nina New/);
  const submit = await p.post('/portal/intake', {
    legal_name: 'Nina New', preferred_name: 'Nina', ssn: '321-54-9876', dob: '1992-09-09', email: 'nina@x.com', phone: '555-2222',
    address_line1: '1 Main St', city: 'Austin', state: 'TX', zip: '78701', filing_status: 'Single',
    dep_name: ['Kid A', ''], dep_relationship: ['Daughter', ''], dep_dob: ['2018-01-01', ''], dep_ssn: ['', ''], message: 'I have crypto income',
  });
  assert.equal(submit.status, 302);
  assert.equal(submit.location, '/portal/home?welcome=1');
  const client = app.ctx.db.prepare("SELECT * FROM clients WHERE legal_name = 'Nina New'").get() as any;
  assert.ok(client);
  assert.equal(client.created_via, 'portal_intake');
  assert.equal(client.ssn_last4, '9876');
  assert.equal(client.source, 'Website');
  assert.match(client.notes, /crypto income/);
  assert.equal((app.ctx.db.prepare('SELECT COUNT(*) c FROM dependents WHERE client_id = ?').get(client.id) as any).c, 1);
  const home = await p.get('/portal/home?welcome=1');
  assert.equal(home.status, 200);
  assert.match(home.text, /intake has been received/);
  const up = await p.upload('/portal/documents', { category: 'Prior-Year Return' }, { name: 'last-year.pdf', content: 'x' });
  assert.equal(up.status, 302);
  assert.equal((app.ctx.db.prepare('SELECT COUNT(*) c FROM documents WHERE client_id = ? AND tax_year = 2025').get(client.id) as any).c, 1);
  // Link is single-use once completed; staff list shows the created record.
  assert.equal((await new Client(app.baseUrl).get(`/portal/new/${token}`)).status, 410);
  const list = await s.get('/clients/intake-links');
  assert.match(list.text, new RegExp(`/clients/${client.id}`));
  const record = await s.get(`/clients/${client.id}`);
  assert.match(record.text, /intake submitted/);
});
