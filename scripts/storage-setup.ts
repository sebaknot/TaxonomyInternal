/** Creates the private Supabase Storage bucket used by the document vault (idempotent). */
import 'dotenv/config';
import { SupabaseStorage } from '../src/lib/storage.js';

const url = process.env.SUPABASE_URL;
const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
const bucket = process.env.SUPABASE_STORAGE_BUCKET || 'vault';
if (!url || !key) {
  console.error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set.');
  process.exit(1);
}
const result = await new SupabaseStorage({ url, serviceRoleKey: key, bucket }).ensureBucket();
console.log(`Bucket "${bucket}": ${result} (private).`);
