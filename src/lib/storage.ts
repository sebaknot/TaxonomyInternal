/**
 * Object storage abstraction. Production uses Supabase Storage through its REST API with the
 * service-role key (server side only). Objects always contain ciphertext; see services/documents.
 */
export interface Storage {
  /** Returns a URL the browser can PUT ciphertext to without any credentials, valid ~2h. */
  createSignedUploadUrl(path: string): Promise<string>;
  /** Returns a short-lived URL the browser can GET ciphertext from. */
  createSignedDownloadUrl(path: string, expiresInSeconds: number): Promise<string>;
  /** Byte size of the stored object, or null if it does not exist. */
  objectSize(path: string): Promise<number | null>;
  /** Server-side put (small objects such as staged imports). */
  put(path: string, body: Uint8Array, contentType?: string): Promise<void>;
  /** Server-side get. */
  get(path: string): Promise<Uint8Array>;
  remove(paths: string[]): Promise<void>;
}

export interface SupabaseStorageOptions {
  url: string; // e.g. https://xyz.supabase.co
  serviceRoleKey: string;
  bucket: string;
  fetchImpl?: typeof fetch;
}

export class SupabaseStorage implements Storage {
  private base: string;
  private fetch: typeof fetch;
  constructor(private opts: SupabaseStorageOptions) {
    this.base = opts.url.replace(/\/$/, '') + '/storage/v1';
    this.fetch = opts.fetchImpl ?? fetch;
  }
  private headers(extra: Record<string, string> = {}) {
    return { Authorization: `Bearer ${this.opts.serviceRoleKey}`, apikey: this.opts.serviceRoleKey, ...extra };
  }
  private enc(path: string) {
    return path.split('/').map(encodeURIComponent).join('/');
  }
  private async check(res: Response, what: string) {
    if (!res.ok) throw new Error(`Supabase Storage ${what} failed: ${res.status} ${(await res.text()).slice(0, 300)}`);
    return res;
  }

  async createSignedUploadUrl(path: string): Promise<string> {
    const res = await this.check(
      await this.fetch(`${this.base}/object/upload/sign/${this.opts.bucket}/${this.enc(path)}`, { method: 'POST', headers: this.headers({ 'content-type': 'application/json' }), body: '{}' }),
      'sign upload',
    );
    const data = (await res.json()) as { url: string };
    return this.base + data.url;
  }

  async createSignedDownloadUrl(path: string, expiresInSeconds: number): Promise<string> {
    const res = await this.check(
      await this.fetch(`${this.base}/object/sign/${this.opts.bucket}/${this.enc(path)}`, {
        method: 'POST',
        headers: this.headers({ 'content-type': 'application/json' }),
        body: JSON.stringify({ expiresIn: expiresInSeconds }),
      }),
      'sign download',
    );
    const data = (await res.json()) as { signedURL: string };
    return this.base + data.signedURL;
  }

  async objectSize(path: string): Promise<number | null> {
    const res = await this.fetch(`${this.base}/object/${this.opts.bucket}/${this.enc(path)}`, { method: 'HEAD', headers: this.headers() });
    if (res.status === 404 || res.status === 400) return null;
    await this.check(res, 'head');
    const len = res.headers.get('content-length');
    return len == null ? null : Number(len);
  }

  async put(path: string, body: Uint8Array, contentType = 'application/octet-stream'): Promise<void> {
    await this.check(
      await this.fetch(`${this.base}/object/${this.opts.bucket}/${this.enc(path)}`, { method: 'POST', headers: this.headers({ 'content-type': contentType, 'x-upsert': 'true' }), body: body as unknown as BodyInit }),
      'put',
    );
  }

  async get(path: string): Promise<Uint8Array> {
    const res = await this.check(await this.fetch(`${this.base}/object/${this.opts.bucket}/${this.enc(path)}`, { headers: this.headers() }), 'get');
    return new Uint8Array(await res.arrayBuffer());
  }

  async remove(paths: string[]): Promise<void> {
    if (!paths.length) return;
    await this.check(
      await this.fetch(`${this.base}/object/${this.opts.bucket}`, { method: 'DELETE', headers: this.headers({ 'content-type': 'application/json' }), body: JSON.stringify({ prefixes: paths }) }),
      'remove',
    );
  }

  /** Creates the private bucket if missing (setup script). */
  async ensureBucket(): Promise<'created' | 'exists'> {
    const existing = await this.fetch(`${this.base}/bucket/${this.opts.bucket}`, { headers: this.headers() });
    if (existing.ok) return 'exists';
    await this.check(
      await this.fetch(`${this.base}/bucket`, {
        method: 'POST',
        headers: this.headers({ 'content-type': 'application/json' }),
        body: JSON.stringify({ id: this.opts.bucket, name: this.opts.bucket, public: false }),
      }),
      'create bucket',
    );
    return 'created';
  }
}
