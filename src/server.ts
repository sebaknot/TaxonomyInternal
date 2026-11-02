import { loadConfig } from './config.js';
import { createApp, createContext } from './app.js';
import { migrate } from './lib/db.js';
import { ensureDefaultTags } from './services/clients.js';

const config = loadConfig();
const ctx = createContext(config);
const app = createApp(ctx);

// Local/long-running mode: apply migrations at boot. On Vercel run `npm run db:migrate` at build time instead.
await migrate(ctx.db);
await ensureDefaultTags(ctx);

app.listen(config.port, () => {
  console.log(`Taxonomy internal platform listening on ${config.baseUrl} (env: ${config.env})`);
  if (!config.smtp) console.log('SMTP not configured: outgoing email is recorded in Admin > Email outbox.');
});
