import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { createApp, createContext } from '../src/app.js';
import type { AppConfig } from '../src/config.js';
import type { AppContext } from '../src/context.js';
import { createUser, getUserById, beginMfaEnrollment, completeMfaEnrollment } from '../src/services/auth.js';
import { totpCode, generateTotpSecret } from '../src/lib/totp.js';
import type { Role } from '../src/lib/constants.js';

export interface TestApp {
  ctx: AppContext;
  server: Server;
  baseUrl: string;
  close: () => Promise<void>;
}

export async function startTestApp(): Promise<TestApp> {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'taxonomy-test-'));
  const config: AppConfig = {
    env: 'test',
    port: 0,
    baseUrl: 'http://localhost',
    dataDir,
    dbPath: path.join(dataDir, 'test.sqlite'),
    encryptionKey: crypto.randomBytes(32),
    sessionSecret: crypto.randomBytes(32),
    cookieSecure: false,
    trustProxy: false,
  };
  const ctx = createContext(config);
  const app = createApp(ctx);
  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  ctx.config.baseUrl = baseUrl;
  return {
    ctx,
    server,
    baseUrl,
    close: async () => {
      await new Promise<void>((r) => server.close(() => r()));
      ctx.db.close();
      fs.rmSync(dataDir, { recursive: true, force: true });
    },
  };
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
  postJson(url: string, body: unknown) {
    return this.request('POST', url, { body: JSON.stringify(body), headers: { 'content-type': 'application/json', accept: 'application/json', 'x-csrf-token': this.csrf } });
  }
  /** Multipart POST with one file. */
  upload(url: string, fields: Record<string, string>, file: { name: string; content: string | Buffer; type?: string }) {
    const fd = new FormData();
    fd.set('_csrf', this.csrf);
    for (const [k, v] of Object.entries(fields)) fd.set(k, v);
    const bytes = typeof file.content === 'string' ? new TextEncoder().encode(file.content) : new Uint8Array(file.content);
    fd.set('file', new Blob([bytes as BlobPart], { type: file.type ?? 'application/pdf' }), file.name);
    return this.request('POST', url, { body: fd });
  }
  async download(url: string) {
    const res = await fetch(this.baseUrl + url, { redirect: 'manual', headers: { cookie: this.cookieHeader() } });
    return { status: res.status, headers: res.headers, body: Buffer.from(await res.arrayBuffer()) };
  }
}

export const PASSWORD = 'correct-horse-battery-1';

/** Creates a user with MFA already enrolled; returns the TOTP secret. */
export function seedUser(ctx: AppContext, email: string, role: Role, name = email.split('@')[0]) {
  const u = createUser(ctx, { email, name, role, password: PASSWORD }, null);
  const secret = beginMfaEnrollment(ctx, u);
  const r = completeMfaEnrollment(ctx, getUserById(ctx, u.id)!, totpCode(secret), {});
  if (!r.ok) throw new Error('enrollment failed');
  return { user: getUserById(ctx, u.id)!, secret, backupCodes: r.backupCodes! };
}

/** Full login: password + TOTP. */
export async function login(client: Client, email: string, secret: string, password = PASSWORD) {
  const r1 = await client.post('/login', { email, password });
  if (r1.status !== 302 || !r1.location?.includes('/mfa')) throw new Error(`password step failed: ${r1.status} ${r1.location}`);
  await client.get('/mfa'); // fetch csrf
  const r2 = await client.post('/mfa', { code: totpCode(secret) });
  if (r2.status !== 302) throw new Error(`mfa step failed: ${r2.status} ${r2.text.slice(0, 200)}`);
  await client.get('/'); // refresh csrf for the authenticated session
  return client;
}

export { totpCode, generateTotpSecret };
