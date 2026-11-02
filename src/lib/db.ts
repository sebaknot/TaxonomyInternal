import pg from 'pg';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const { Pool, types } = pg;

// Keep timestamps and JSON as strings so templates and services treat them uniformly.
types.setTypeParser(1184, (v) => new Date(v).toISOString()); // timestamptz
types.setTypeParser(1114, (v) => new Date(v + 'Z').toISOString()); // timestamp
types.setTypeParser(1082, (v) => v); // date -> 'YYYY-MM-DD'
types.setTypeParser(20, (v) => Number(v)); // int8 (COUNT(*))
types.setTypeParser(1700, (v) => Number(v)); // numeric
types.setTypeParser(3802, (v) => v); // jsonb -> raw string
types.setTypeParser(114, (v) => v); // json -> raw string

export interface Queryable {
  query<T = any>(sql: string, params?: unknown[]): Promise<{ rows: T[]; rowCount: number }>;
}

/**
 * Thin async wrapper over node-postgres. SQL may use `?` placeholders (converted to $1..$n
 * outside of string literals) so queries read naturally. Every method is safe to call from
 * a serverless invocation; nothing is cached in process memory.
 */
export class DB {
  constructor(private readonly q: Queryable, private readonly pool?: pg.Pool) {}

  static fromUrl(databaseUrl: string, opts: { max?: number } = {}): DB {
    const pool = new Pool({
      connectionString: databaseUrl,
      max: opts.max ?? 5,
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 10_000,
      ssl: needsSsl(databaseUrl) ? { rejectUnauthorized: false } : undefined,
    });
    return new DB(pool, pool);
  }

  async query<T = any>(sql: string, params: unknown[] = []): Promise<{ rows: T[]; rowCount: number }> {
    const r = await this.q.query<T>(toPositional(sql), params);
    return { rows: r.rows, rowCount: r.rowCount ?? 0 };
  }
  async all<T = any>(sql: string, ...params: unknown[]): Promise<T[]> {
    return (await this.query<T>(sql, params)).rows;
  }
  async one<T = any>(sql: string, ...params: unknown[]): Promise<T | undefined> {
    return (await this.query<T>(sql, params)).rows[0];
  }
  /** Runs a statement; resolves to the affected row count. */
  async run(sql: string, ...params: unknown[]): Promise<number> {
    return (await this.query(sql, params)).rowCount;
  }
  async scalar<T = any>(sql: string, ...params: unknown[]): Promise<T> {
    const row = await this.one<Record<string, T>>(sql, ...params);
    return row ? (Object.values(row)[0] as T) : (undefined as T);
  }

  /** Runs fn inside a transaction on a dedicated connection. Nested calls reuse the outer transaction. */
  async tx<T>(fn: (db: DB) => Promise<T>): Promise<T> {
    if (!this.pool) return fn(this); // already inside a transaction (or a single client)
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await fn(new DB(client));
      await client.query('COMMIT');
      return result;
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch {}
      throw err;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool?.end();
  }
}

function needsSsl(url: string): boolean {
  if (/sslmode=disable/.test(url)) return false;
  if (/sslmode=require|sslmode=verify/.test(url)) return true;
  return !/localhost|127\.0\.0\.1/.test(url);
}

/** Converts `?` placeholders to `$1..$n`, ignoring question marks inside single-quoted literals. */
export function toPositional(sql: string): string {
  let out = '';
  let n = 0;
  let inQuote = false;
  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    if (ch === "'") inQuote = !inQuote;
    if (ch === '?' && !inQuote) {
      // `??` or `?|`/`?&` are jsonb operators; not used here, treat every bare ? as a placeholder.
      out += `$${++n}`;
    } else out += ch;
  }
  return out;
}

// ---------- Migrations ----------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
/** supabase/migrations at the repo root, whether running from src/ (tsx) or dist/src/ (compiled). */
export const MIGRATIONS_DIR = [
  path.resolve(__dirname, '../../supabase/migrations'),
  path.resolve(__dirname, '../../../supabase/migrations'),
  path.resolve(process.cwd(), 'supabase/migrations'),
].find((p) => fs.existsSync(p)) ?? path.resolve(process.cwd(), 'supabase/migrations');

/** Applies every *.sql file in supabase/migrations (sorted) that is not yet recorded. Idempotent. */
export async function migrate(db: DB, dir = MIGRATIONS_DIR): Promise<string[]> {
  await db.run(`CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`);
  const applied = new Set((await db.all<{ name: string }>('SELECT name FROM schema_migrations')).map((r) => r.name));
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();
  const ran: string[] = [];
  for (const f of files) {
    if (applied.has(f)) continue;
    const sql = fs.readFileSync(path.join(dir, f), 'utf8');
    await db.tx(async (t) => {
      await t.query(sql);
      await t.run('INSERT INTO schema_migrations (name) VALUES (?)', f);
    });
    ran.push(f);
  }
  return ran;
}
