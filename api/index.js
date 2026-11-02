// Vercel serverless entry point. The whole Express app runs inside one function; state lives in
// Postgres (sessions, lockouts, rate limits) and Supabase Storage, never in process memory.
import { loadConfig } from '../dist/src/config.js';
import { createApp, createContext } from '../dist/src/app.js';

const app = createApp(createContext(loadConfig()));
export default app;
