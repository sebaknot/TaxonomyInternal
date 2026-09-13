import crypto from 'node:crypto';

/**
 * Field-level encryption for sensitive values (SSNs, MFA secrets).
 * AES-256-GCM, random 12-byte IV, output "v1:<iv b64>:<tag b64>:<ct b64>".
 * The AAD binds the ciphertext to a context label so a value cannot be
 * swapped between columns/records.
 */
export class FieldCipher {
  constructor(private key: Buffer) {
    if (key.length !== 32) throw new Error('FieldCipher requires a 32-byte key');
  }

  encrypt(plaintext: string, context = 'field'): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from(context));
    const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `v1:${iv.toString('base64')}:${tag.toString('base64')}:${ct.toString('base64')}`;
  }

  decrypt(payload: string, context = 'field'): string {
    const [v, ivB64, tagB64, ctB64] = payload.split(':');
    if (v !== 'v1' || !ivB64 || !tagB64 || !ctB64) throw new Error('Malformed encrypted payload');
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, Buffer.from(ivB64, 'base64'));
    decipher.setAAD(Buffer.from(context));
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(ctB64, 'base64')), decipher.final()]).toString('utf8');
  }

  /** Streaming helpers for file-at-rest encryption. Header: 12-byte IV; trailer: 16-byte tag. */
  fileEncryptor(): { iv: Buffer; cipher: crypto.CipherGCM } {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    return { iv, cipher };
  }
  fileDecryptor(iv: Buffer, tag: Buffer): crypto.DecipherGCM {
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, iv);
    decipher.setAuthTag(tag);
    return decipher;
  }
}

/** Password hashing with scrypt (Node built-in, no native deps). Format: scrypt$N$r$p$salt$hash */
const SCRYPT = { N: 1 << 15, r: 8, p: 1, keylen: 64 };
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password.normalize('NFKC'), salt, SCRYPT.keylen, {
    N: SCRYPT.N,
    r: SCRYPT.r,
    p: SCRYPT.p,
    maxmem: 128 * SCRYPT.N * SCRYPT.r * 2,
  });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}
export function verifyPassword(password: string, stored: string): boolean {
  try {
    const [alg, N, r, p, saltB64, hashB64] = stored.split('$');
    if (alg !== 'scrypt') return false;
    const expected = Buffer.from(hashB64, 'base64');
    const actual = crypto.scryptSync(password.normalize('NFKC'), Buffer.from(saltB64, 'base64'), expected.length, {
      N: Number(N),
      r: Number(r),
      p: Number(p),
      maxmem: 128 * Number(N) * Number(r) * 2,
    });
    return crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

export function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}
export function sha256(input: string | Buffer): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}
export function hmac(key: Buffer, input: string): string {
  return crypto.createHmac('sha256', key).update(input).digest('base64url');
}
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
export function newId(): string {
  return crypto.randomUUID();
}
