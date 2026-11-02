/** Applies pending SQL migrations from supabase/migrations to DATABASE_URL. Safe to run repeatedly. */
import 'dotenv/config';
import { DB, migrate } from '../src/lib/db.js';

const url = process.env.DATABASE_URL;
if (!url) {
  console.error('DATABASE_URL is not set.');
  process.exit(1);
}
const db = DB.fromUrl(url, { max: 1 });
try {
  const ran = await migrate(db);
  console.log(ran.length ? `Applied: ${ran.join(', ')}` : 'Database is up to date.');
} finally {
  await db.close();
}
