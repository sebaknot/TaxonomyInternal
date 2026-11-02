/**
 * Applies pending SQL migrations from supabase/migrations. Safe to run repeatedly.
 * Uses DIRECT_DATABASE_URL when set (Supabase session-mode pooler or direct connection), otherwise
 * DATABASE_URL. DDL runs fine through either, but the session/direct connection is recommended by
 * Supabase for migrations and avoids transaction-pooler restrictions on long-running statements.
 */
import 'dotenv/config';
import { DB, migrate } from '../src/lib/db.js';

const url = process.env.DIRECT_DATABASE_URL || process.env.DATABASE_URL;
if (!url) {
  console.error('DATABASE_URL (or DIRECT_DATABASE_URL) is not set.');
  process.exit(1);
}
if (!process.env.DIRECT_DATABASE_URL && /pooler\.supabase\.com:6543/.test(url)) {
  console.warn('Note: migrating through the transaction pooler (port 6543). Set DIRECT_DATABASE_URL to the session pooler (port 5432) if a migration fails.');
}
const db = DB.fromUrl(url, { max: 1 });
try {
  const ran = await migrate(db);
  console.log(ran.length ? `Applied: ${ran.join(', ')}` : 'Database is up to date.');
} catch (err) {
  console.error('Migration failed:', (err as Error).message);
  process.exitCode = 1;
} finally {
  await db.close();
}
