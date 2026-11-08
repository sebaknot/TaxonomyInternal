import crypto from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import pg from 'pg';
import { createApp, createContext } from '../src/app.js';
import type { AppConfig } from '../src/config.js';
import type { AppContext } from '../src/context.js';
import { DB, migrate } from '../src/lib/db.js';
import { SupabaseStorage } from '../src/lib/storage.js';
import { ensureDefaultTags } from '../src/services/clients.js';
import { createUser, getUserById, beginMfaEnrollment, completeMfaEnrollment } from '../src/services/auth.js';
import { totpCode, generateTotpSecret } from '../src/lib/totp.js';
import type { Role } from '../src/lib/constants.js';

/** Maintenance connection used to create one throwaway database per test file (so files can run in parallel). */
export const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL || 'postgres://postgres@127.0.0.1:5432/postgres';

export async function createTestDatabase(): Promise<{ url: string; drop: () => Promise<void> }> {
  const name = `taxonomy_test_${crypto.randomBytes(6).toString('hex')}`;
  const admin = new pg.Client({ connectionString: TEST_DATABASE_URL });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${name}`);
  await admin.end();
  const u = new URL(TEST_DATABASE_URL);
  u.pathname = `/${name}`;
  return {
    url: u.toString(),
    drop: async () => {
      const a = new pg.Client({ connectionString: TEST_DATABASE_URL });
      await a.connect();
      await a.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      await a.end();
    },
  };
}

/**
 * In-memory stand-in for the Supabase Storage REST API (the subset the adapter uses):
 * signed upload URLs, PUT to a signed URL, signed download URLs, HEAD/GET/POST/DELETE objects, buckets.
 */
export class FakeSupabaseStorageServer {
  objects = new Map<string, { body: Buffer; contentType: string }>();
  tokens = new Map<string, { path: string; kind: 'upload' | 'download'; expires: number }>();
  buckets = new Set<string>(['vault']);
  server!: Server;
  url = '';
  requests: { method: string; path: string; auth: string | undefined }[] = [];
  readonly serviceKey = 'service-role-test-key';

  async start() {
    this.server = http.createServer((req, res) => this.handle(req, res));
    await new Promise<void>((r) => this.server.listen(0, '127.0.0.1', r));
    this.url = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
    return this;
  }
  async stop() {
    await new Promise<void>((r) => this.server.close(() => r()));
  }
  private read(req: http.IncomingMessage): Promise<Buffer> {
    return new Promise((resolve) => {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => resolve(Buffer.concat(chunks)));
    });
  }
  private json(res: http.ServerResponse, status: number, body: unknown) {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  }
  private async handle(req: http.IncomingMessage, res: http.ServerResponse) {
    const url = new URL(req.url!, this.url);
    const method = req.method!;
    this.requests.push({ method, path: url.pathname, auth: req.headers.authorization });
    const authed = req.headers.authorization === `Bearer ${this.serviceKey}`;
    const p = url.pathname.replace(/^\/storage\/v1/, '');
    const dec = (s: string) => s.split('/').map(decodeURIComponent).join('/');

    // Signed-URL endpoints usable WITHOUT credentials (what the browser hits).
    let m = p.match(/^\/object\/upload\/sign\/([^/]+)\/(.+)$/);
    if (m && method === 'PUT') {
      const t = this.tokens.get(url.searchParams.get('token') || '');
      if (!t || t.kind !== 'upload' || t.path !== `${m[1]}/${dec(m[2])}` || t.expires < Date.now()) return this.json(res, 403, { error: 'invalid token' });
      const body = await this.read(req);
      this.objects.set(t.path, { body, contentType: req.headers['content-type'] || 'application/octet-stream' });
      return this.json(res, 200, { Key: t.path });
    }
    m = p.match(/^\/object\/sign\/([^/]+)\/(.+)$/);
    if (m && method === 'GET') {
      const t = this.tokens.get(url.searchParams.get('token') || '');
      if (!t || t.kind !== 'download' || t.path !== `${m[1]}/${dec(m[2])}` || t.expires < Date.now()) return this.json(res, 403, { error: 'invalid token' });
      const obj = this.objects.get(t.path);
      if (!obj) return this.json(res, 404, { error: 'not found' });
      res.writeHead(200, { 'content-type': obj.contentType, 'content-length': String(obj.body.length) });
      return res.end(obj.body);
    }

    if (!authed) return this.json(res, 401, { error: 'unauthorized' });

    if (m && method === 'POST') {
      // create signed download URL
      const path = `${m[1]}/${dec(m[2])}`;
      if (!this.objects.has(path)) return this.json(res, 404, { error: 'Object not found' });
      const body = JSON.parse((await this.read(req)).toString() || '{}');
      const token = crypto.randomBytes(16).toString('hex');
      this.tokens.set(token, { path, kind: 'download', expires: Date.now() + (body.expiresIn ?? 60) * 1000 });
      return this.json(res, 200, { signedURL: `/object/sign/${m[1]}/${m[2]}?token=${token}` });
    }
    m = p.match(/^\/object\/upload\/sign\/([^/]+)\/(.+)$/);
    if (m && method === 'POST') {
      const token = crypto.randomBytes(16).toString('hex');
      this.tokens.set(token, { path: `${m[1]}/${dec(m[2])}`, kind: 'upload', expires: Date.now() + 2 * 3600_000 });
      return this.json(res, 200, { url: `/object/upload/sign/${m[1]}/${m[2]}?token=${token}` });
    }
    m = p.match(/^\/object\/([^/]+)\/(.+)$/);
    if (m) {
      const path = `${m[1]}/${dec(m[2])}`;
      const obj = this.objects.get(path);
      if (method === 'HEAD') {
        if (!obj) return this.json(res, 404, { error: 'not found' });
        res.writeHead(200, { 'content-length': String(obj.body.length), 'content-type': obj.contentType });
        return res.end();
      }
      if (method === 'GET') {
        if (!obj) return this.json(res, 404, { error: 'not found' });
        res.writeHead(200, { 'content-type': obj.contentType, 'content-length': String(obj.body.length) });
        return res.end(obj.body);
      }
      if (method === 'POST' || method === 'PUT') {
        const body = await this.read(req);
        this.objects.set(path, { body, contentType: req.headers['content-type'] || 'application/octet-stream' });
        return this.json(res, 200, { Key: path });
      }
    }
    m = p.match(/^\/object\/([^/]+)$/);
    if (m && method === 'DELETE') {
      const body = JSON.parse((await this.read(req)).toString() || '{}') as { prefixes: string[] };
      for (const pre of body.prefixes || []) this.objects.delete(`${m[1]}/${pre}`);
      return this.json(res, 200, []);
    }
    m = p.match(/^\/bucket\/([^/]+)$/);
    if (m && method === 'GET') return this.buckets.has(m[1]) ? this.json(res, 200, { id: m[1], public: false }) : this.json(res, 404, { error: 'Bucket not found' });
    if (p === '/bucket' && method === 'POST') {
      const body = JSON.parse((await this.read(req)).toString());
      this.buckets.add(body.id);
      return this.json(res, 200, { name: body.id });
    }
    this.json(res, 404, { error: `unhandled ${method} ${p}` });
  }
}

export interface TestApp {
  ctx: AppContext;
  server: Server;
  baseUrl: string;
  storageServer: FakeSupabaseStorageServer;
  config: AppConfig;
  /** Boots a second, independent app process-equivalent against the same database and storage. */
  spawnSibling: () => Promise<{ baseUrl: string; close: () => Promise<void> }>;
  close: () => Promise<void>;
}

/**
 * Minimal in-process SMTP server (plain text, optional AUTH, no STARTTLS) for mailer tests.
 * `mode` controls behaviour: 'ok' accepts everything; 'reject' answers 550 at RCPT; 'drop' closes the socket.
 */
export class FakeSmtpServer {
  mode: 'ok' | 'reject' | 'drop' = 'ok';
  messages: { from: string; to: string[]; data: string; authed: boolean }[] = [];
  readonly user = 'smtp-user';
  readonly pass = 'smtp-pass-secret';
  server!: net.Server;
  port = 0;
  async start() {
    this.server = net.createServer((sock) => this.handle(sock));
    await new Promise<void>((r) => this.server.listen(0, '127.0.0.1', r));
    this.port = (this.server.address() as AddressInfo).port;
    return this;
  }
  async stop() {
    await new Promise<void>((r) => this.server.close(() => r()));
  }
  private handle(sock: net.Socket) {
    if (this.mode === 'drop') return sock.destroy();
    let from = '';
    const to: string[] = [];
    let authed = false;
    let inData = false;
    let data = '';
    let buf = '';
    const reply = (s: string) => sock.write(s + '\r\n');
    reply('220 fake-smtp ESMTP');
    sock.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      let idx: number;
      while ((idx = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        if (inData) {
          if (line === '.') {
            inData = false;
            this.messages.push({ from, to: [...to], data, authed });
            data = '';
            reply('250 OK queued');
          } else data += line + '\n';
          continue;
        }
        const up = line.toUpperCase();
        if (up.startsWith('EHLO') || up.startsWith('HELO')) reply('250-fake-smtp\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME');
        else if (up.startsWith('AUTH PLAIN')) {
          const [, , b64] = line.split(' ');
          const [, u, p] = Buffer.from(b64 || '', 'base64').toString().split('\0');
          authed = u === this.user && p === this.pass;
          reply(authed ? '235 Authentication successful' : '535 Authentication credentials invalid');
        } else if (up.startsWith('MAIL FROM')) {
          from = line.slice(line.indexOf('<') + 1, line.indexOf('>'));
          reply('250 OK');
        } else if (up.startsWith('RCPT TO')) {
          if (this.mode === 'reject') reply('550 5.1.1 Mailbox unavailable: recipient rejected');
          else {
            to.push(line.slice(line.indexOf('<') + 1, line.indexOf('>')));
            reply('250 OK');
          }
        } else if (up === 'DATA') {
          inData = true;
          reply('354 End data with <CR><LF>.<CR><LF>');
        } else if (up === 'QUIT') {
          reply('221 Bye');
          sock.end();
        } else if (up === 'RSET' || up === 'NOOP') reply('250 OK');
        else reply('500 Unrecognised command');
      }
    });
    sock.on('error', () => {});
  }
}

export async function startTestApp(opts: { bootstrapToken?: string; smtp?: FakeSmtpServer } = {}): Promise<TestApp> {
  const database = await createTestDatabase();
  const storageServer = await new FakeSupabaseStorageServer().start();
  const config: AppConfig = {
    env: 'test',
    port: 0,
    baseUrl: 'http://localhost',
    databaseUrl: database.url,
    dbPoolMax: 4,
    supabaseUrl: storageServer.url,
    supabaseServiceRoleKey: storageServer.serviceKey,
    storageBucket: 'vault',
    encryptionKey: crypto.randomBytes(32),
    sessionSecret: crypto.randomBytes(32),
    cookieSecure: false,
    trustProxy: false,
    cronSecret: 'cron-test-secret',
    bootstrapToken: opts.bootstrapToken,
    directDatabaseUrl: database.url,
    smtp: opts.smtp ? { host: '127.0.0.1', port: opts.smtp.port, secure: false, user: opts.smtp.user, pass: opts.smtp.pass, from: 'Taxonomy <no-reply@taxonomy.test>' } : undefined,
  };
  const db = DB.fromUrl(config.databaseUrl, { max: config.dbPoolMax });
  await migrate(db);
  const ctx = createContext(config, { db });
  await ensureDefaultTags(ctx);
  const listen = async (c: AppContext) => {
    const app = createApp(c);
    const server = await new Promise<Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    return { server, baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
  };
  const main = await listen(ctx);
  ctx.config.baseUrl = main.baseUrl;
  const siblings: { server: Server; db: DB }[] = [];
  return {
    ctx,
    server: main.server,
    baseUrl: main.baseUrl,
    storageServer,
    config,
    spawnSibling: async () => {
      const sdb = DB.fromUrl(config.databaseUrl, { max: 2 });
      const sctx = createContext({ ...config, baseUrl: main.baseUrl }, { db: sdb });
      const s = await listen(sctx);
      siblings.push({ server: s.server, db: sdb });
      return { baseUrl: s.baseUrl, close: async () => {} };
    },
    close: async () => {
      for (const s of siblings) {
        await new Promise<void>((r) => s.server.close(() => r()));
        await s.db.close();
      }
      await new Promise<void>((r) => main.server.close(() => r()));
      await ctx.db.close();
      await storageServer.stop();
      await database.drop();
    },
  };
}

export function storageClientFor(app: TestApp): SupabaseStorage {
  return new SupabaseStorage({ url: app.storageServer.url, serviceRoleKey: app.storageServer.serviceKey, bucket: 'vault' });
}

/** Minimal cookie-jar HTTP client (no redirects followed, so tests can assert on them). */
export class Client {
  cookies = new Map<string, string>();
  csrf = '';
  constructor(public baseUrl: string) {}

  private cookieHeader() {
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }
  private storeCookies(res: Response) {
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const [pair, ...attrs] = c.split(';');
      const idx = pair.indexOf('=');
      const name = pair.slice(0, idx).trim();
      const value = pair.slice(idx + 1).trim();
      const expired = attrs.some((a) => /expires=Thu, 01 Jan 1970/i.test(a) || /max-age=0/i.test(a));
      if (expired || value === '') this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }
  async request(method: string, url: string, init: { body?: BodyInit; headers?: Record<string, string> } = {}) {
    const res = await fetch(this.baseUrl + url, { method, redirect: 'manual', body: init.body, headers: { cookie: this.cookieHeader(), ...(init.headers ?? {}) } });
    this.storeCookies(res);
    const text = await res.text();
    const m = text.match(/name="csrf" content="([^"]*)"/);
    if (m && m[1]) this.csrf = m[1];
    return { status: res.status, headers: res.headers, text, location: res.headers.get('location') };
  }
  get(url: string) {
    return this.request('GET', url);
  }
  /** Form POST; the CSRF token from the last fetched page is added automatically. */
  post(url: string, fields: Record<string, string | string[]> = {}, opts: { csrf?: string } = {}) {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(fields)) for (const x of ([] as string[]).concat(v)) params.append(k, x);
    params.set('_csrf', opts.csrf ?? this.csrf);
    return this.request('POST', url, { body: params, headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  }
  postJson(url: string, body: unknown, opts: { csrf?: string } = {}) {
    return this.request('POST', url, { body: JSON.stringify(body), headers: { 'content-type': 'application/json', accept: 'application/json', 'x-csrf-token': opts.csrf ?? this.csrf } });
  }
  /** Multipart POST with one file (spreadsheet imports). */
  upload(url: string, fields: Record<string, string>, file: { name: string; content: string | Buffer; type?: string }) {
    const fd = new FormData();
    fd.set('_csrf', this.csrf);
    for (const [k, v] of Object.entries(fields)) fd.set(k, v);
    const bytes = typeof file.content === 'string' ? new TextEncoder().encode(file.content) : new Uint8Array(file.content);
    fd.set('file', new Blob([bytes as BlobPart], { type: file.type ?? 'application/pdf' }), file.name);
    return this.request('POST', url, { body: fd });
  }

  /**
   * Performs the browser's encrypted upload protocol: init -> AES-GCM encrypt -> PUT ciphertext to the
   * signed URL -> complete. Returns the completion JSON.
   */
  async encryptedUpload(initUrl: string, completeUrlTemplate: string, fields: Record<string, string | number | null>, file: { name: string; content: string | Buffer; type?: string }) {
    const content = typeof file.content === 'string' ? Buffer.from(file.content) : file.content;
    const init = await this.postJson(initUrl, { filename: file.name, size: content.length, mime: file.type ?? 'application/pdf', ...fields });
    if (init.status !== 200) return { status: init.status, text: init.text, init: null as any, complete: null as any };
    const grant = JSON.parse(init.text) as { versionId: string; uploadUrl: string; key: string; iv: string };
    const key = Buffer.from(grant.key, 'base64');
    const iv = Buffer.from(grant.iv, 'base64');
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(content), cipher.final(), cipher.getAuthTag()]);
    const put = await fetch(grant.uploadUrl, { method: 'PUT', headers: { 'content-type': 'application/octet-stream' }, body: ciphertext });
    if (!put.ok) throw new Error(`PUT to signed URL failed: ${put.status}`);
    const sha256 = crypto.createHash('sha256').update(content).digest('hex');
    const complete = await this.postJson(completeUrlTemplate.replace('VERSION_ID', grant.versionId), { sha256, size: content.length });
    return { status: complete.status, text: complete.text, init: grant, complete: complete.status === 200 ? JSON.parse(complete.text) : null };
  }

  /** Performs the browser's download protocol: grant -> GET ciphertext -> decrypt. */
  async encryptedDownload(grantUrl: string): Promise<{ status: number; body: Buffer | null; filename?: string }> {
    const g = await this.postJson(grantUrl, {});
    if (g.status !== 200) return { status: g.status, body: null };
    const grant = JSON.parse(g.text) as { url: string; key: string; iv: string; filename: string };
    const res = await fetch(grant.url);
    if (!res.ok) return { status: res.status, body: null };
    const ct = Buffer.from(await res.arrayBuffer());
    const tag = ct.subarray(ct.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(grant.key, 'base64'), Buffer.from(grant.iv, 'base64'));
    decipher.setAuthTag(tag);
    return { status: 200, body: Buffer.concat([decipher.update(ct.subarray(0, ct.length - 16)), decipher.final()]), filename: grant.filename };
  }
}

export const PASSWORD = 'correct-horse-battery-1';

/** Creates a user with MFA already enrolled; returns the TOTP secret. */
export async function seedUser(ctx: AppContext, email: string, role: Role, name = email.split('@')[0]) {
  const u = await createUser(ctx, { email, name, role, password: PASSWORD }, null);
  const secret = await beginMfaEnrollment(ctx, u);
  const r = await completeMfaEnrollment(ctx, (await getUserById(ctx, u.id))!, totpCode(secret), {});
  if (!r.ok) throw new Error('enrollment failed');
  return { user: (await getUserById(ctx, u.id))!, secret, backupCodes: r.backupCodes! };
}

/** Full login: password + TOTP. */
export async function login(client: Client, email: string, secret: string, password = PASSWORD) {
  const r1 = await client.post('/login', { email, password });
  if (r1.status !== 302 || !r1.location?.includes('/mfa')) throw new Error(`password step failed: ${r1.status} ${r1.location}`);
  await client.get('/mfa');
  const r2 = await client.post('/mfa', { code: totpCode(secret) });
  if (r2.status !== 302) throw new Error(`mfa step failed: ${r2.status} ${r2.text.slice(0, 200)}`);
  await client.get('/');
  return client;
}

export { totpCode, generateTotpSecret };
