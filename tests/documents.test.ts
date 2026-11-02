import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startTestApp, Client, seedUser, login, type TestApp } from './helpers.js';
import { createClient } from '../src/services/clients.js';
import { getVersion } from '../src/services/documents.js';

let app: TestApp;
type Seed = Awaited<ReturnType<typeof seedUser>>;
let admin: Seed, preparer: Seed, intake: Seed;
before(async () => {
  app = await startTestApp();
  admin = await seedUser(app.ctx, 'admin@example.com', 'admin');
  preparer = await seedUser(app.ctx, 'prep@example.com', 'preparer');
  intake = await seedUser(app.ctx, 'intake@example.com', 'intake');
});
after(async () => app.close());
const sys = { type: 'system' as const, label: 'test' };
const INIT = (clientId: string) => `/clients/${clientId}/documents/init`;
const COMPLETE = '/documents/uploads/VERSION_ID/complete';

test('direct encrypted upload: storage holds only ciphertext, versions are kept, download decrypts and is audited', async () => {
  const client = await createClient(app.ctx, { legal_name: 'Doc Client', assigned_preparer_id: preparer.user.id }, sys);
  const c = await login(new Client(app.baseUrl), preparer.user.email, preparer.secret);
  await c.get(`/clients/${client.id}`);
  const content = Buffer.from('%PDF-1.4 hello world W-2 content ' + 'x'.repeat(5000));
  const up = await c.encryptedUpload(INIT(client.id), COMPLETE, { tax_year: 2025, category: 'W-2s' }, { name: 'w2 acme.pdf', content });
  assert.equal(up.status, 200, up.text);
  const docId = up.complete.documentId as string;
  const doc = await app.ctx.db.one<any>('SELECT * FROM documents WHERE id = ?', docId);
  assert.equal(doc.tax_year, 2025);
  assert.equal(doc.category, 'W-2s');
  assert.equal(doc.status, 'uploaded');
  const v1 = (await getVersion(app.ctx, up.init.versionId))!;
  assert.equal(v1.original_filename, 'w2 acme.pdf');
  assert.equal(v1.uploaded_by_label, preparer.user.email);
  assert.equal(Number(v1.size_bytes), content.length);
  assert.equal(v1.upload_state, 'complete');
  assert.equal(v1.sha256, crypto.createHash('sha256').update(content).digest('hex'));
  assert.match(v1.uploaded_at!, /^\d{4}-\d\d-\d\dT/);
  // What Supabase Storage holds is ciphertext of exactly plaintext+tag bytes, and the DB holds only a wrapped key.
  const stored = app.storageServer.objects.get(`vault/${v1.storage_path}`)!;
  assert.ok(stored, 'object exists in the bucket');
  assert.equal(stored.body.length, content.length + 16);
  assert.ok(!stored.body.includes(Buffer.from('hello world')), 'object must be encrypted');
  assert.match(v1.data_key_enc, /^v1:/);
  assert.ok(!v1.data_key_enc.includes(up.init.key.slice(0, 10)));
  // The PUT went to the signed URL without any credentials.
  const put = app.storageServer.requests.find((r) => r.method === 'PUT');
  assert.ok(put && !put.auth, 'browser upload carries no service key');

  // New version through the same protocol with replace_document_id: both kept.
  await c.get(`/documents/${docId}`);
  const up2 = await c.encryptedUpload(INIT(client.id), COMPLETE, { tax_year: 2025, category: 'W-2s', replace_document_id: docId }, { name: 'w2 acme corrected.pdf', content: 'second version' });
  assert.equal(up2.status, 200, up2.text);
  assert.equal(up2.complete.documentId, docId);
  const versions = await app.ctx.db.all<any>('SELECT * FROM document_versions WHERE document_id = ? ORDER BY version_no', docId);
  assert.equal(versions.length, 2);
  assert.equal(versions[1].version_no, 2);
  const page = await c.get(`/documents/${docId}`);
  assert.match(page.text, /w2 acme\.pdf/);
  assert.match(page.text, /w2 acme corrected\.pdf/);

  // Download grant + decrypt: latest and the old version.
  const dl = await c.encryptedDownload(`/documents/${docId}/download`);
  assert.equal(dl.status, 200);
  assert.equal(dl.body!.toString(), 'second version');
  assert.equal(dl.filename, 'w2 acme corrected.pdf');
  const old = await c.encryptedDownload(`/documents/${docId}/versions/${versions[0].id}/download`);
  assert.ok(old.body!.equals(content));
  const audits = (await app.ctx.db.all<{ action: string }>("SELECT action FROM audit_log WHERE client_id = ? AND action LIKE 'document.%' ORDER BY id", client.id)).map((a) => a.action);
  assert.deepEqual(audits, ['document.upload', 'document.new_version', 'document.download', 'document.download']);

  const show = await c.get(`/clients/${client.id}`);
  assert.match(show.text, /Tax year 2025/);
  assert.match(show.text, /W-2s/);
  assert.match(show.text, /data-encrypted-upload/);
});

test('completion is refused when the object is missing, the size is wrong, or someone else tries to finish it', async () => {
  const client = await createClient(app.ctx, { legal_name: 'Tamper Client' }, sys);
  const a = await login(new Client(app.baseUrl), admin.user.email, admin.secret);
  await a.get(`/clients/${client.id}`);
  const init = await a.postJson(INIT(client.id), { filename: 'x.pdf', size: 100, tax_year: 2024, category: 'Other' });
  assert.equal(init.status, 200);
  const g = JSON.parse(init.text);
  const sha = 'a'.repeat(64);
  // Nothing uploaded yet.
  let r = await a.postJson(`/documents/uploads/${g.versionId}/complete`, { sha256: sha, size: 100 });
  assert.equal(r.status, 400);
  assert.match(JSON.parse(r.text).error, /did not reach storage/);
  // Wrong-sized object (ciphertext must be plaintext + 16).
  app.storageServer.objects.set(`vault/clients/${client.id}/${g.uploadUrl.split('/').pop()!.split('?')[0]}`, { body: Buffer.alloc(50), contentType: 'x' });
  r = await a.postJson(`/documents/uploads/${g.versionId}/complete`, { sha256: sha, size: 100 });
  assert.equal(r.status, 400);
  assert.match(JSON.parse(r.text).error, /unexpected size/);
  // Right size but a different staff member tries to complete it.
  const v = (await getVersion(app.ctx, g.versionId))!;
  app.storageServer.objects.set(`vault/${v.storage_path}`, { body: Buffer.alloc(116), contentType: 'x' });
  const i = await login(new Client(app.baseUrl), intake.user.email, intake.secret);
  await i.get(`/clients/${client.id}`);
  r = await i.postJson(`/documents/uploads/${g.versionId}/complete`, { sha256: sha, size: 100 });
  assert.equal(r.status, 400);
  assert.match(JSON.parse(r.text).error, /someone else/);
  // Owner completes; a second completion is rejected.
  r = await a.postJson(`/documents/uploads/${g.versionId}/complete`, { sha256: sha, size: 100 });
  assert.equal(r.status, 200);
  r = await a.postJson(`/documents/uploads/${g.versionId}/complete`, { sha256: sha, size: 100 });
  assert.equal(r.status, 400);
  // Pending (never completed) uploads never show in the vault.
  const init2 = await a.postJson(INIT(client.id), { filename: 'ghost.pdf', size: 10, tax_year: 2024, category: 'Other' });
  assert.equal(init2.status, 200);
  const show = await a.get(`/clients/${client.id}`);
  assert.doesNotMatch(show.text, /ghost\.pdf/);
});

test('status workflow: rejected requires a reason; intake can upload/download but not set status', async () => {
  const client = await createClient(app.ctx, { legal_name: 'Status Client' }, sys);
  const a = await login(new Client(app.baseUrl), admin.user.email, admin.secret);
  await a.get(`/clients/${client.id}`);
  const up = await a.encryptedUpload(INIT(client.id), COMPLETE, { tax_year: 2024, category: '1099s' }, { name: 'form.png', content: 'img', type: 'image/png' });
  const docId = up.complete.documentId;
  await a.get(`/documents/${docId}`);
  await a.post(`/documents/${docId}/status`, { status: 'rejected', reason: '' });
  let doc = await app.ctx.db.one<any>('SELECT * FROM documents WHERE id = ?', docId);
  assert.equal(doc.status, 'uploaded');
  await a.post(`/documents/${docId}/status`, { status: 'rejected', reason: 'Blurry scan' });
  doc = await app.ctx.db.one<any>('SELECT * FROM documents WHERE id = ?', docId);
  assert.equal(doc.status, 'rejected');
  assert.equal(doc.rejection_reason, 'Blurry scan');
  await a.post(`/documents/${docId}/status`, { status: 'accepted' });
  doc = await app.ctx.db.one<any>('SELECT * FROM documents WHERE id = ?', docId);
  assert.equal(doc.status, 'accepted');
  assert.equal(doc.rejection_reason, null);

  const i = await login(new Client(app.baseUrl), intake.user.email, intake.secret);
  await i.get(`/documents/${docId}`);
  assert.equal((await i.post(`/documents/${docId}/status`, { status: 'reviewed' })).status, 403);
  const iu = await i.encryptedUpload(INIT(client.id), COMPLETE, { tax_year: 2024, category: 'Other' }, { name: 'id.jpg', content: 'jpg' });
  assert.equal(iu.status, 200);
  assert.equal((await i.encryptedDownload(`/documents/${docId}/download`)).status, 200);
});

test('disallowed file types and oversized files are refused at init; other preparers cannot reach the document', async () => {
  const client = await createClient(app.ctx, { legal_name: 'Other Client' }, sys);
  const a = await login(new Client(app.baseUrl), admin.user.email, admin.secret);
  await a.get(`/clients/${client.id}`);
  const bad = await a.postJson(INIT(client.id), { filename: 'evil.exe', size: 10, tax_year: 2024, category: 'Other' });
  assert.equal(bad.status, 400);
  const big = await a.postJson(INIT(client.id), { filename: 'big.pdf', size: 30 * 1024 * 1024, tax_year: 2024, category: 'Other' });
  assert.equal(big.status, 400);
  assert.match(JSON.parse(big.text).error, /too large/);
  assert.equal(await app.ctx.db.scalar('SELECT COUNT(*) FROM document_versions WHERE client_id = ?', client.id), 0);
  const ok = await a.encryptedUpload(INIT(client.id), COMPLETE, { tax_year: 2024, category: 'Other' }, { name: 'ok.pdf', content: 'pdf' });
  const docId = ok.complete.documentId;
  const p = await login(new Client(app.baseUrl), preparer.user.email, preparer.secret);
  assert.equal((await p.get(`/documents/${docId}`)).status, 404);
  assert.equal((await p.postJson(`/documents/${docId}/download`, {})).status, 404);
  assert.equal((await p.postJson(INIT(client.id), { filename: 'x.pdf', size: 1, tax_year: 2024, category: 'Other' })).status, 404);
});
