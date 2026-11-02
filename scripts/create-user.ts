/**
 * Create a staff user from the command line (used to bootstrap the first Owner/Admin).
 *   npm run create-user -- --email you@firm.com --name "Your Name" --role admin --password 'a-strong-passphrase-1'
 */
import { loadConfig } from '../src/config.js';
import { createContext } from '../src/app.js';
import { createUser } from '../src/services/auth.js';
import { ROLES, type Role } from '../src/lib/constants.js';

const args = new Map<string, string>();
for (let i = 2; i < process.argv.length; i += 2) args.set(process.argv[i].replace(/^--/, ''), process.argv[i + 1] ?? '');
const email = args.get('email');
const name = args.get('name');
const role = (args.get('role') || 'admin') as Role;
const password = args.get('password') || process.env.NEW_USER_PASSWORD;
if (!email || !name || !password || !ROLES.includes(role)) {
  console.error('Usage: npm run create-user -- --email <email> --name "<name>" --role <admin|manager|preparer|intake|bookkeeper> --password <password>');
  process.exit(1);
}
const ctx = createContext(loadConfig());
try {
  const u = await createUser(ctx, { email, name, role, password }, null);
  console.log(`Created ${u.role} ${u.email} (${u.id}). They will enroll two-factor authentication at first sign-in.`);
} catch (err) {
  console.error((err as Error).message);
  process.exitCode = 1;
} finally {
  await ctx.db.close();
}
