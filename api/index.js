// Vercel serverless entry point. The whole Express app runs inside one function; state lives in
// Postgres (sessions, lockouts, rate limits) and Supabase Storage, never in process memory.
import { loadConfig, ConfigError } from '../dist/src/config.js';
import { createApp, createContext } from '../dist/src/app.js';

let handler;
try {
  handler = createApp(createContext(loadConfig()));
} catch (err) {
  // Misconfiguration must be obvious, not a generic FUNCTION_INVOCATION_FAILED. The message only
  // names variables; it never contains values.
  const message = err instanceof ConfigError ? err.message : `The application failed to start: ${err && err.message ? err.message : String(err)}`;
  console.error(message);
  handler = (_req, res) => {
    res.statusCode = 503;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end(`Taxonomy Internal is not configured.\n\n${message}\n`);
  };
}
export default handler;
