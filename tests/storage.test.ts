import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startTestApp, storageClientFor, type TestApp } from './helpers.js';
import { SupabaseStorage } from '../src/lib/storage.js';
import { encryptForUpload, decryptDownloaded, uploadFromServer, unwrapKey, cleanupPendingUploads, getVersion } from '../src/services/documents.js';
import { createClient } from '../src/services/clients.js';

let app: TestApp;
before(async () => {
  app = await startTestApp();
});
after(async () => app.close());
const sys = { type: 'system' as const, label: 'test' };

test('SupabaseStorage adapter: signed upload URL, HEAD, signed download, server put/get, remove, bucket setup', async () => {
  const storage = storageClientFor(app);
  const path = `clients/test/${crypto.randomUUID()}.bin`;
  assert.equal(await storage.objectSize(path), null);

  // Signed upload: PUT with no credentials (what the browser does).
  const uploadUrl = await storage.createSignedUploadUrl(path);
  assert.match(uploadUrl, /\/storage\/v1\/object\/upload\/sign\/vault\/clients\/test\/.+\?token=/);
  const bytes = crypto.randomBytes(1234);
  const put = await fetch(uploadUrl, { method: 'PUT', headers: { 'content-type': 'application/octet-stream' }, body: bytes });
  assert.equal(put.status, 200);
  assert.equal(await storage.objectSize(path), 1234);
  // A bad token is refused by storage.
  const forged = await fetch(uploadUrl.replace(/token=.*/, 'token=forged'), { method: 'PUT', body: 'x' });
  assert.equal(forged.status, 403);

  // Signed download: GET with no credentials.
  const dlUrl = await storage.createSignedDownloadUrl(path, 60);
  const got = await fetch(dlUrl);
  assert.equal(got.status, 200);
  assert.ok(Buffer.from(await got.arrayBuffer()).equals(bytes));

  // Server-side put/get (used for staged imports).
  const p2 = `imports/${crypto.randomUUID()}.bin`;
  await storage.put(p2, new Uint8Array([1, 2, 3]));
  assert.deepEqual([...(await storage.get(p2))], [1, 2, 3]);
  await storage.remove([path, p2]);
  assert.equal(await storage.objectSize(path), null);
  await assert.rejects(storage.get(p2), /get failed: 404/);

  // Every authenticated call carries the service-role key as a bearer token; signed-URL calls carry none.
  const authed = app.storageServer.requests.filter((r) => r.auth);
  assert.ok(authed.length >= 5);
  assert.ok(authed.every((r) => r.auth === `Bearer ${app.storageServer.serviceKey}`));
  assert.ok(app.storageServer.requests.some((r) => r.method === 'PUT' && !r.auth));

  // Bucket bootstrap is idempotent and private.
  const other = new SupabaseStorage({ url: app.storageServer.url, serviceRoleKey: app.storageServer.serviceKey, bucket: 'fresh-bucket' });
  assert.equal(await other.ensureBucket(), 'created');
  assert.equal(await other.ensureBucket(), 'exists');
  // Wrong key is rejected.
  const bad = new SupabaseStorage({ url: app.storageServer.url, serviceRoleKey: 'wrong', bucket: 'vault' });
  await assert.rejects(bad.createSignedUploadUrl('x'), /401/);
});

test('envelope encryption: AES-256-GCM round trip, tamper detection, keys never stored in the clear', async () => {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const plaintext = Buffer.from('Form 1099-INT, interest income $412.33');
  const { ciphertext, sha256 } = encryptForUpload(plaintext, key, iv);
  assert.equal(ciphertext.length, plaintext.length + 16);
  assert.equal(sha256, crypto.createHash('sha256').update(plaintext).digest('hex'));
  assert.ok(decryptDownloaded(ciphertext, key, iv).equals(plaintext));
  const tampered = Buffer.from(ciphertext);
  tampered[3] ^= 0xff;
  assert.throws(() => decryptDownloaded(tampered, key, iv), /Unsupported state|unable to authenticate/);
  assert.throws(() => decryptDownloaded(ciphertext, crypto.randomBytes(32), iv));

  // Through the service: the stored object is ciphertext and the DB row only holds a wrapped key.
  const client = await createClient(app.ctx, { legal_name: 'Envelope Client' }, sys);
  const { version } = await uploadFromServer(app.ctx, { clientId: client.id, taxYear: 2025, category: 'Investments', originalFilename: '1099-int.pdf', content: plaintext }, sys);
  const obj = app.storageServer.objects.get(`vault/${version.storage_path}`)!;
  assert.ok(!obj.body.includes(Buffer.from('interest income')));
  const unwrapped = unwrapKey(app.ctx, version);
  assert.ok(decryptDownloaded(obj.body, unwrapped.key, unwrapped.iv).equals(plaintext));
  const rawRow = await app.ctx.db.one<{ t: string }>('SELECT (v.*)::text t FROM document_versions v WHERE id = ?', version.id);
  assert.ok(!rawRow!.t.includes(unwrapped.key.toString('base64')), 'raw data key never appears in the database');
  // A different master key cannot unwrap it.
  const { FieldCipher } = await import('../src/lib/crypto.js');
  assert.throws(() => unwrapKey({ ...app.ctx, cipher: new FieldCipher(crypto.randomBytes(32)) }, version));
});

test('abandoned pending uploads are swept by the cron cleanup, including their storage objects', async () => {
  const client = await createClient(app.ctx, { legal_name: 'Sweep Client' }, sys);
  const { initUpload } = await import('../src/services/documents.js');
  const init = await initUpload(app.ctx, { clientId: client.id, taxYear: 2025, category: 'Other', originalFilename: 'abandoned.pdf', sizeBytes: 10 }, sys);
  const v = (await getVersion(app.ctx, init.versionId))!;
  app.storageServer.objects.set(`vault/${v.storage_path}`, { body: Buffer.alloc(26), contentType: 'x' });
  assert.equal(await cleanupPendingUploads(app.ctx), 0, 'fresh pending uploads are left alone');
  await app.ctx.db.run("UPDATE document_versions SET created_at = now() - interval '2 days' WHERE id = ?", v.id);
  const unauthorized = await fetch(`${app.baseUrl}/api/cron/cleanup`);
  assert.equal(unauthorized.status, 401);
  const res = await fetch(`${app.baseUrl}/api/cron/cleanup`, { headers: { authorization: 'Bearer cron-test-secret' } });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.pendingUploads, 1);
  assert.equal(await getVersion(app.ctx, v.id), undefined);
  assert.ok(!app.storageServer.objects.has(`vault/${v.storage_path}`));
});

test('row level security is enabled on every table with no policies, so API roles can read nothing', async () => {
  const tables = await app.ctx.db.all<{ tablename: string; rowsecurity: boolean }>("SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public'");
  assert.ok(tables.length >= 15);
  for (const t of tables) assert.equal(t.rowsecurity, true, `${t.tablename} must have RLS enabled`);
  assert.equal(await app.ctx.db.scalar("SELECT COUNT(*) FROM pg_policies WHERE schemaname = 'public'"), 0);
  // Simulate the Supabase `anon` API role: a non-owner role without BYPASSRLS sees zero rows.
  const role = `rls_probe_${crypto.randomBytes(4).toString('hex')}`;
  await app.ctx.db.run(`CREATE ROLE ${role} NOLOGIN`);
  await app.ctx.db.run(`GRANT USAGE ON SCHEMA public TO ${role}`);
  await app.ctx.db.run(`GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${role}`);
  await createClient(app.ctx, { legal_name: 'Hidden From Anon' }, sys);
  const visible = await app.ctx.db.tx(async (t) => {
    await t.run(`SET LOCAL ROLE ${role}`);
    return t.scalar<number>('SELECT COUNT(*) FROM clients');
  });
  assert.equal(visible, 0);
  assert.ok((await app.ctx.db.scalar<number>('SELECT COUNT(*) FROM clients')) >= 1);
  await app.ctx.db.run(`REVOKE ALL ON ALL TABLES IN SCHEMA public FROM ${role}`);
  await app.ctx.db.run(`REVOKE USAGE ON SCHEMA public FROM ${role}`);
  await app.ctx.db.run(`DROP ROLE ${role}`);
});
