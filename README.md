# Taxonomy Internal Platform — Build 1: Foundation

Internal tax-practice management platform for Taxonomy, deployed on **Vercel** (serverless) with **Supabase** (Postgres + Storage). This build delivers the secure foundation:

- **Authentication & roles** — five roles (Owner/Admin, Manager, Tax Preparer, Intake Staff, Bookkeeper), mandatory TOTP two-factor authentication, configurable idle timeout (default 15 min), new-device / new-location admin alerts, instant per-user revocation, and a full audit log of every login, logout and failed attempt.
- **Client records** — encrypted SSNs (AES-256-GCM at rest, masked as `***-**-1234` everywhere; Admin can reveal with an explicit, audited action), dependents, spouse, filing status, assigned preparer, specialization tags, source, notes, year-by-year history, auto-calculated years as client. Every edit is audited with the changed fields.
- **Bulk import** — CSV / Excel (TaxWise-style export) with per-column mapping and a created/failed summary with per-row reasons.
- **Document vault** — organized by tax year → category; every upload records uploader, timestamp, filename, year, category; staff-settable status (Uploaded / Reviewed / Accepted / Rejected + reason); re-uploads create a new version and never overwrite. Files are **encrypted in the browser** and uploaded straight to Supabase Storage.
- **Client portal (magic links)** — returning-client links gated by last-4 SSN + date of birth, with "No changes" / "Update" per section and document upload straight into the vault; new-client intake links with an identity step then a full intake form that creates the record. Every client action is logged and shown on the client record.

Not in this build (by design): engagement letters / e-sign, payments, pipeline dashboard, calendar, visual design, OCR, SMS. The UI is intentionally plain.

## Architecture

| Concern | Where it lives |
|---|---|
| Web app | Express 5 + EJS, one Vercel serverless function (`api/index.js`) |
| Data | Supabase Postgres via `pg`, schema in `supabase/migrations/*.sql` |
| Sessions, MFA state, lockouts, rate limits | Postgres tables — nothing is kept in process memory, so any instance can serve any request |
| Files | Supabase Storage, private bucket; objects are AES-256-GCM ciphertext produced in the browser |
| Secrets | `APP_ENCRYPTION_KEY` (master key) and `SUPABASE_SERVICE_ROLE_KEY` exist only in the server environment |

### How file encryption works

1. The browser asks the server to start an upload (`POST /clients/:id/documents/init`). The server creates a pending version row, generates a random 256-bit **data key** and IV, stores the data key wrapped with the master key, and returns a **signed upload URL** plus the raw data key.
2. The browser encrypts the file with WebCrypto AES-256-GCM and `PUT`s the ciphertext directly to Supabase Storage using the signed URL. The bytes never pass through Vercel, so the 4.5 MB request limit does not apply (25 MB files are supported).
3. The browser reports the plaintext SHA-256 and size; the server verifies the object exists with exactly `size + 16` bytes and finalises the document.
4. To download, the server unwraps the key, writes an audit entry, and returns a 2-minute signed download URL plus the key. The browser fetches the ciphertext and decrypts locally.

Supabase therefore only ever stores ciphertext and wrapped keys; SSNs, MFA secrets and data keys are encrypted with `APP_ENCRYPTION_KEY` before they reach Postgres.

### Database security

- **Row Level Security is enabled on every table with no policies.** The app connects as the table owner through `DATABASE_URL` (not subject to RLS); the Supabase API roles (`anon`, `authenticated`) are also stripped of grants by the migration, so the auto-generated REST/GraphQL API exposes nothing.
- The storage bucket is private. Access is only through signed URLs minted by the server with the service-role key.
- Staged import files are encrypted server-side before they are written to Storage and are deleted after the import runs.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | yes | Supabase Postgres URI. **On Vercel use the transaction-pooler URI** (port 6543) from *Dashboard → Connect*. |
| `SUPABASE_URL` | yes | Project URL, e.g. `https://xyz.supabase.co`. |
| `SUPABASE_SERVICE_ROLE_KEY` | yes | Service-role key (*Project Settings → API*). Server-side only; bypasses RLS. Never expose to the browser. |
| `APP_ENCRYPTION_KEY` | yes | 32 random bytes, base64. Encrypts SSNs, MFA secrets and per-file data keys. Generate with `npm run gen-keys`. **Back it up separately; losing it makes the data unrecoverable. Never rotate casually.** |
| `SESSION_SECRET` | yes | 32+ random bytes, base64. Signs device cookies. |
| `BASE_URL` | recommended | Public URL used in magic links (no trailing slash). Defaults to `https://$VERCEL_URL`. |
| `SUPABASE_STORAGE_BUCKET` | no | Bucket name, default `vault`. |
| `CRON_SECRET` | recommended | Bearer token Vercel Cron sends to `/api/cron/cleanup` (purges expired sessions, stale rate-limit rows, abandoned uploads). |
| `COOKIE_SECURE` | see note | Secure cookie flag. Defaults to `true` on Vercel. **Must be `true` when `NODE_ENV=production`; the app refuses to start otherwise.** |
| `TRUST_PROXY` | no | Read client IP from `X-Forwarded-For`. Defaults to `true` on Vercel. |
| `NODE_ENV` | no | `production` on Vercel. |
| `DB_POOL_MAX` | no | Connections per instance (default 2 on Vercel, 5 elsewhere). |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` | no | Outgoing email for alerts and portal links. Without SMTP, messages are recorded in *Admin → Email outbox*. |
| `PORT` | no | Local dev port (default 3000). |
| `TEST_DATABASE_URL` | tests | Postgres the test suite may create/drop throwaway databases in. |

`.env.example` lists the same variables with comments.

## Deploying to Vercel + Supabase

1. **Create a Supabase project.** Note the project URL, the service-role key, and the *transaction pooler* connection string (*Connect → Transaction pooler*, port 6543). The direct connection (port 5432) is fine for local use and for running migrations.
2. **Generate secrets locally:** `npm run gen-keys` prints `APP_ENCRYPTION_KEY` and `SESSION_SECRET`. Store them in a password manager as well as in Vercel.
3. **Apply the schema and create the bucket** (from your machine, with the variables in `.env`):
   ```bash
   npm install
   npm run db:migrate       # applies supabase/migrations/*.sql, enables RLS
   npm run storage:setup    # creates the private "vault" bucket
   ```
   You can also apply the SQL with the Supabase CLI (`supabase db push`) since the files follow its layout.
4. **Create the first Owner/Admin:**
   ```bash
   npm run create-user -- --email you@firm.com --name "Your Name" --role admin --password 'a-strong-passphrase-1'
   ```
5. **Import the repo into Vercel.** Framework preset: *Other*. `vercel.json` sets the build command (`npm run build && npm run db:migrate`, so pending migrations run on every deploy), routes everything to the single function, includes the EJS views, and schedules the nightly cleanup cron. Add every variable from the table above in *Project → Settings → Environment Variables*, with `NODE_ENV=production`.
6. **Deploy.** Then set `BASE_URL` to the final domain and redeploy so magic links use it.
7. Sign in and enroll your authenticator app. Users enroll two-factor on first sign-in; eight one-time backup codes are shown once.

Operational notes:

- Vercel's 4.5 MB request limit applies only to the import tool (spreadsheets); documents bypass the server entirely.
- Back up the database with Supabase's backups and keep `APP_ENCRYPTION_KEY` with it; neither is useful without the other.
- Rotating `SUPABASE_SERVICE_ROLE_KEY` or `SESSION_SECRET` is safe at any time (users may need to sign in again). Rotating `APP_ENCRYPTION_KEY` requires re-encrypting all data and is not supported in this build.

## Local development

```bash
npm install
npm run gen-keys && cp .env.example .env     # fill in DATABASE_URL, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY and the keys
npm run db:migrate && npm run storage:setup
npm run create-user -- --email you@firm.com --name "You" --role admin --password 'a-strong-passphrase-1'
COOKIE_SECURE=false npm run dev                 # http://localhost:3000
```

A local Supabase stack (`supabase start`) works too: use its Postgres URL, API URL and service-role key.

## Roles and permissions

| Capability | Admin | Manager | Preparer | Intake | Bookkeeper |
|---|---|---|---|---|---|
| Manage users, settings, audit log, alerts | ✔ | | | | |
| Reveal full SSN (audited) | ✔ | | | | |
| See all clients | ✔ | ✔ | assigned only | ✔ | |
| Create clients | ✔ | ✔ | | ✔ | |
| Edit clients / dependents | ✔ | ✔ | assigned only | ✔ (no notes/fees/SSN digits) | |
| Assign preparer | ✔ | ✔ | | | |
| Bulk import | ✔ | ✔ | | | |
| Upload / download documents | ✔ | ✔ | assigned only | ✔ | |
| Set document status | ✔ | ✔ | assigned only | | |
| Generate portal links | ✔ | ✔ | assigned only | ✔ | |

Bookkeeper exists for Build 3 (payments) and has no data access yet. The policy lives in `src/services/permissions.ts`.

## Security design

- Passwords: scrypt (N=2^15) with per-user salt; 12-char minimum; lockout for 15 min after 5 failures (counter stored on the user row); login/MFA/portal endpoints rate-limited per IP in the `rate_limits` table.
- Sessions: random 256-bit token stored hashed in Postgres; `HttpOnly`, `SameSite=Lax`, `Secure` cookies; idle timeout (admin-configurable) + 12-hour absolute lifetime; per-session CSRF token on every state-changing request.
- MFA: RFC 6238 TOTP (secret encrypted at rest) + hashed one-time backup codes; a password-only session can reach nothing but the MFA step.
- Revocation: deactivating a user deletes all their sessions immediately; every request re-checks the user is still active.
- Alerts: a signed device cookie and the source IP are compared with the user's known devices/IPs; unknown ones create an alert in *Admin → Alerts* and email all admins.
- Encryption at rest: AES-256-GCM with per-record AAD for SSNs (client, spouse, dependents), MFA secrets and per-file data keys; files are encrypted end-to-end in the browser (see above).
- Magic links: 256-bit tokens stored hashed, expire after a configurable number of hours (default 72), locked after 5 failed verifications, revocable by staff, shown to staff only once.
- Headers: Helmet CSP (`default-src 'self'`, `connect-src` limited to the app and the Supabase project), no-referrer, `Cache-Control: no-store`, HSTS when HTTPS is enabled.
- Audit log: append-only table capturing actor, action, entity, client, details, IP and user agent — *Admin → Audit log*, and per client at `/clients/:id/audit`.

## Tests

The suite runs against a real Postgres server and an in-process stand-in for the Supabase Storage REST API. Each test file creates and drops its own database, so files run in parallel.

```bash
# any Postgres 14+ you can create databases in (local install, Docker, or `supabase start`)
TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres npm test
npm run typecheck
```

Coverage: login + mandatory MFA + backup codes, idle timeout and its admin setting, new-device alerts, revocation, lockout, CSRF, SSN encryption/masking/reveal audit, role isolation, edit audit, years-as-client, dependents, the full encrypted upload protocol (init → PUT to signed URL → complete, tamper and ownership checks, versions, download grants), CSV and Excel import with mapping and failure reporting, returning-client and new-client portal flows, the Storage adapter, envelope-encryption invariants, RLS on every table, cross-instance sessions / lockouts / rate limits, and the cron cleanup.

## Layout

```
api/index.js          Vercel serverless entry (imports the built app)
vercel.json           build command, routing, cron, function config
supabase/migrations/  SQL schema (RLS enabled, no policies)
public/static/        CSS + browser crypto/upload script (served by Vercel CDN)
src/
  app.ts              express app factory (createContext / createApp)
  server.ts           long-running entrypoint for local dev
  config.ts           env config (fails fast on missing keys / insecure cookies)
  lib/                db (pg wrapper + migration runner), storage (Supabase REST), crypto, TOTP
  middleware/         sessions/CSRF/flash, DB-backed rate limiter + cleanup
  services/           auth, permissions, clients, documents, imports, magic links, audit, settings, mailer
  routes/             auth, clients, documents, imports, admin, portal
  views/              EJS templates (plain, unstyled by design)
scripts/              gen-keys, create-user, db-migrate, storage-setup
tests/                node:test suites + fake Supabase Storage server
```
