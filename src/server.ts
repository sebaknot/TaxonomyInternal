import { loadConfig } from './config.js';
import { createApp, createContext } from './app.js';

const config = loadConfig();
const ctx = createContext(config);
const app = createApp(ctx);
app.listen(config.port, () => {
  console.log(`Taxonomy internal platform listening on ${config.baseUrl} (data: ${config.dataDir}, env: ${config.env})`);
  if (!config.smtp) console.log('SMTP not configured: outgoing email is recorded in Admin > Email outbox.');
});
