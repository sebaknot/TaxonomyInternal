import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { startTestApp, Client, seedUser, login, type TestApp } from './helpers.js';
import { createClient } from '../src/services/clients.js';

let app: TestApp;
let admin: ReturnType<typeof seedUser>;
let preparer: ReturnType<typeof seedUser>;
let intake: ReturnType<typeof seedUser>;
before(async () => {
  app = await startTestApp();
  admin = seedUser(app.ctx, 'admin@example.com', 'admin');
  preparer = seedUser(app.ctx, 'prep@example.com', 'preparer');
  intake = seedUser(app.ctx, 'intake@example.com', 'intake');
});
after(async () => app.close());
const sys = { type: 'system' as const, label: 'test' };

test('upload records metadata, encrypts at rest, versions are kept, download decrypts and is audited', async () => {
  const client = createClient(app.ctx, { legal_name: 'Doc Client', assigned_preparer_id: preparer.user.id }, sys);
  const c = await login(new Client(app.baseUrl), preparer.user.email, preparer.secret);
  await c.get(`/clients/${client.id}`);
  const content = Buffer.from('%PDF-1.4 hello world W-2 content ' + 'x'.repeat(5000));
  const up = await c.upload(`/clients/${client.id}/documents`, { tax_year: '2025', category: 'W-2s' }, { name: 'w2 acme.pdf', content });
  assert.equal(up.status, 302);
  const docId = up.location!.split('/').pop()!;
  const doc = app.ctx.db.prepare('SELECT * FROM documents WHERE id = ?').get(docId) as any;
  assert.equal(doc.tax_year, 2025);
  assert.equal(doc.category, 'W-2s');
  assert.equal(doc.status, 'uploaded');
  const v1 = app.ctx.db.prepare('SELECT * FROM document_versions WHERE document_id = ?').get(docId) as any;
  assert.equal(v1.original_filename, 'w2 acme.pdf');
  assert.equal(v1.uploaded_by_label, preparer.user.email);
  assert.equal(v1.size_bytes, content.length);
  assert.match(v1.uploaded_at, /^\d{4}-\d\d-\d\dT/);
  const stored = fs.readFileSync(path.join(app.ctx.uploadsDir, v1.stored_name));
  assert.ok(!stored.includes('hello world'), 'file must be encrypted on disk');
  // temp dir cleaned
  assert.equal(fs.readdirSync(path.join(app.ctx.config.dataDir, 'tmp')).length, 0);

  // New version: both kept.
  await c.get(`/documents/${docId}`);
  const up2 = await c.upload(`/documents/${docId}/versions`, {}, { name: 'w2 acme corrected.pdf', content: 'second version' });
  assert.equal(up2.status, 302);
  const versions = app.ctx.db.prepare('SELECT * FROM document_versions WHERE document_id = ? ORDER BY version_no').all(docId) as any[];
  assert.equal(versions.length, 2);
  assert.equal(versions[1].version_no, 2);
  const page = await c.get(`/documents/${docId}`);
  assert.match(page.text, /w2 acme\.pdf/);
  assert.match(page.text, /w2 acme corrected\.pdf/);

  // Download of latest decrypts to original bytes; old version still downloadable.
  const dl = await c.download(`/documents/${docId}/download`);
  assert.equal(dl.status, 200);
  assert.equal(dl.body.toString(), 'second version');
  assert.match(dl.headers.get('content-disposition')!, /attachment/);
  const old = await c.download(`/documents/${docId}/versions/${versions[0].id}/download`);
  assert.ok(old.body.equals(content));
  const audits = app.ctx.db.prepare("SELECT action FROM audit_log WHERE client_id = ? AND action LIKE 'document.%' ORDER BY id").all(client.id) as any[];
  assert.deepEqual(audits.map((a) => a.action), ['document.upload', 'document.new_version', 'document.download', 'document.download']);

  // Vault on the client record groups by year then category.
  const show = await c.get(`/clients/${client.id}`);
  assert.match(show.text, /Tax year 2025/);
  assert.match(show.text, /W-2s/);
});

test('status workflow: rejected requires a reason; intake cannot set status', async () => {
  const client = createClient(app.ctx, { legal_name: 'Status Client' }, sys);
  const a = await login(new Client(app.baseUrl), admin.user.email, admin.secret);
  await a.get(`/clients/${client.id}`);
  const up = await a.upload(`/clients/${client.id}/documents`, { tax_year: '2024', category: '1099s' }, { name: 'form.png', content: 'img' });
  const docId = up.location!.split('/').pop()!;
  await a.get(`/documents/${docId}`);
  await a.post(`/documents/${docId}/status`, { status: 'rejected', reason: '' });
  let doc = app.ctx.db.prepare('SELECT * FROM documents WHERE id = ?').get(docId) as any;
  assert.equal(doc.status, 'uploaded');
  await a.post(`/documents/${docId}/status`, { status: 'rejected', reason: 'Blurry scan' });
  doc = app.ctx.db.prepare('SELECT * FROM documents WHERE id = ?').get(docId) as any;
  assert.equal(doc.status, 'rejected');
  assert.equal(doc.rejection_reason, 'Blurry scan');
  await a.post(`/documents/${docId}/status`, { status: 'accepted' });
  doc = app.ctx.db.prepare('SELECT * FROM documents WHERE id = ?').get(docId) as any;
  assert.equal(doc.status, 'accepted');
  assert.equal(doc.rejection_reason, null);

  const i = await login(new Client(app.baseUrl), intake.user.email, intake.secret);
  await i.get(`/documents/${docId}`);
  assert.equal((await i.post(`/documents/${docId}/status`, { status: 'reviewed' })).status, 403);
  // Intake can upload and download.
  const iu = await i.upload(`/clients/${client.id}/documents`, { tax_year: '2024', category: 'Other' }, { name: 'id.jpg', content: 'jpg' });
  assert.equal(iu.status, 302);
  assert.equal((await i.download(`/documents/${docId}/download`)).status, 200);
});

test('disallowed file types are rejected; preparers cannot reach documents of other clients', async () => {
  const client = createClient(app.ctx, { legal_name: 'Other Client' }, sys);
  const a = await login(new Client(app.baseUrl), admin.user.email, admin.secret);
  await a.get(`/clients/${client.id}`);
  const bad = await a.upload(`/clients/${client.id}/documents`, { tax_year: '2024', category: 'Other' }, { name: 'evil.exe', content: 'MZ' });
  assert.equal(bad.status, 400);
  const ok = await a.upload(`/clients/${client.id}/documents`, { tax_year: '2024', category: 'Other' }, { name: 'ok.pdf', content: 'pdf' });
  const docId = ok.location!.split('/').pop()!;
  const p = await login(new Client(app.baseUrl), preparer.user.email, preparer.secret);
  assert.equal((await p.get(`/documents/${docId}`)).status, 404);
  assert.equal((await p.download(`/documents/${docId}/download`)).status, 404);
});
