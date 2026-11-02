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
| `DIRECT_DATABASE_URL` | recommended | Connection used only by `npm run db:migrate` (including the Vercel build). Use the **session pooler** URI (pooler host, port 5432). Falls back to `DATABASE_URL`. See *Migrations and pooling* below. |
| `SUPABASE_URL` | yes | Project URL, e.g. `https://xyz.supabase.co`. |
| `SUPABASE_SERVICE_ROLE_KEY` | yes | Service-role key (*Project Settings → API*). Server-side only; bypasses RLS. Never expose to the browser. |
| `APP_ENCRYPTION_KEY` | yes | 32 random bytes, base64. Encrypts SSNs, MFA secrets and per-file data keys. Generate with `npm run gen-keys`. **Back it up separately; losing it makes the data unrecoverable. Never rotate casually.** |
| `SESSION_SECRET` | yes | 32+ random bytes, base64. Signs device cookies. |
| `BASE_URL` | recommended | Public URL used in magic links (no trailing slash). Defaults to `https://$VERCEL_URL`. |
| `SUPABASE_STORAGE_BUCKET` | no | Bucket name, default `vault`. |
| `BOOTSTRAP_TOKEN` | setup only | Long random string that unlocks `/setup` while the users table is empty. **Remove it after the first admin exists.** |
| `CRON_SECRET` | recommended | Bearer token Vercel Cron sends to `/api/cron/cleanup` (purges expired sessions, stale rate-limit rows, abandoned uploads). |
| `COOKIE_SECURE` | see note | Secure cookie flag. Defaults to `true` on Vercel. **Must be `true` when `NODE_ENV=production`; the app refuses to start otherwise.** |
| `TRUST_PROXY` | no | Read client IP from `X-Forwarded-For`. Defaults to `true` on Vercel. |
| `NODE_ENV` | no | `production` on Vercel. |
| `DB_POOL_MAX` | no | Connections per instance (default 2 on Vercel, 5 elsewhere). |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` | no | Outgoing email for alerts and portal links. Without SMTP, messages are recorded in *Admin → Email outbox*. |
| `PORT` | no | Local dev port (default 3000). |
| `TEST_DATABASE_URL` | tests | Postgres the test suite may create/drop throwaway databases in. |

`.env.example` lists the same variables with comments. If any required variable is missing or malformed, the app does not start: locally the process exits with a message listing every problem; on Vercel every request returns a plain-text `503` naming the variables (never their values). `/health` reports whether the database and storage answer.

### Migrations and pooling

- **Runtime** (`DATABASE_URL`): use Supabase's *transaction pooler* (port 6543). The app uses unnamed parameterised queries and short transactions only, which the pooler supports, and keeps 2 connections per function instance.
- **Migrations** (`DIRECT_DATABASE_URL`): use the *session pooler* (same host, port 5432) or the direct connection. The runner applies each file inside a transaction using the simple query protocol; this works through the transaction pooler too, but Supabase recommends session mode for DDL, and the direct host `db.<ref>.supabase.co` is IPv6-only on most plans and therefore unreachable from Vercel's build environment. The session pooler is IPv4-reachable. Both Vercel and local `npm run db:migrate` pick `DIRECT_DATABASE_URL` when present.
- The Vercel build command (`npm run vercel-build`) runs `build`, `db:migrate` and `storage:setup`, so every deploy applies pending migrations and makes sure the private bucket exists. Both steps are idempotent.

### Storage bucket, CORS and limits

- The bucket is created by `npm run storage:setup` (also during the Vercel build) as **private**. `/health` fails if the bucket is missing or has been made public.
- Signed upload/download URLs are served by Supabase's Storage API, which answers CORS preflight for any origin, so the browser's cross-origin `PUT`/`GET` needs no bucket configuration. The app's Content-Security-Policy allows `connect-src` to the Supabase origin only.
- Signed upload URLs are valid for 2 hours and single-object; download URLs for 2 minutes. The app limits documents to 25 MB; Supabase's global file-size limit (50 MB on the free tier) is above that.

### Vercel configuration notes

- One Node 22 serverless function (`api/index.js`) handles every route via a catch-all rewrite; files under `public/` (CSS and the browser crypto script) are served by the CDN first.
- `maxDuration` is 30 s, within every plan's limit. No `memory` override is set so the config is valid on Hobby.
- The cleanup cron runs **once a day** (`0 4 * * *`), which is the most frequent schedule the Hobby plan allows (Hobby crons fire within an hour of the scheduled time). Pro/Enterprise may shorten it.
- `CRON_SECRET` must be set in the environment for Vercel to send the bearer token the endpoint checks.

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
4. **Choose how to create the first Owner/Admin.** Either in the browser after deploy (recommended, no secrets pasted anywhere: set a `BOOTSTRAP_TOKEN` as described in *First login* below) or from your machine:
   ```bash
   npm run create-user -- --email you@firm.com --name "Your Name" --role admin --password 'a-strong-passphrase-1'
   ```
5. **Import the repo into Vercel.** Framework preset: *Other*. `vercel.json` sets the build command (`npm run build && npm run db:migrate`, so pending migrations run on every deploy), routes everything to the single function, includes the EJS views, and schedules the nightly cleanup cron. Add every variable from the table above in *Project → Settings → Environment Variables*, with `NODE_ENV=production`.
6. **Deploy.** Then set `BASE_URL` to the final domain and redeploy so magic links use it.
7. Open `/health` on the deployment. It must report `"status": "ok"` with `database.ok` and `storage.ok` both true. If not, the `detail` fields say what to fix (missing schema → run migrations; missing bucket → `npm run storage:setup`; auth failures → check the service-role key or `DATABASE_URL` password).
8. Follow *First login* below.

### First login (bootstrap the first admin without pasting secrets)

1. Generate a token on your machine: `openssl rand -base64 32`. Add it in Vercel as `BOOTSTRAP_TOKEN` and redeploy. `/health` now shows `"bootstrap": { "setupOpen": true }`.
2. Open `https://<your-domain>/setup`. The page exists only while the users table is empty **and** the token is configured; otherwise it is a 404.
3. Enter the bootstrap token (it is sent in the form body, never in the URL). Wrong tokens are audited and rate-limited (10 attempts per 15 minutes per IP).
4. Enter your name, sign-in email and a password of 12+ characters with letters and numbers. This creates the Owner/Admin account and signs you in with a password-only session.
5. You are taken straight to **two-factor setup**: scan the QR code with an authenticator app, or type the manual key shown under it, then enter the 6-digit code.
6. **Save the eight one-time backup codes** shown next. They are not displayed again.
7. The dashboard opens. `/setup` is now permanently a 404 for everyone, and `/health` shows `setupOpen: false` with a note to remove the token.
8. **Remove `BOOTSTRAP_TOKEN`** from Vercel (*Settings → Environment Variables → delete*) and redeploy. The route is already dead while a user exists; removing the variable is defence in depth.

Every step is recorded in the audit log (`setup.token_rejected`, `setup.token_accepted`, `setup.admin_created`, then the normal `auth.*` entries). If you abandon the flow after the account is created but before enrolling two-factor, sign in at `/login`; enrollment resumes there.

### What to test with fake data

Use obviously fake values (names like "Test Taxpayer", SSNs such as `123-45-6789`, throwaway email addresses). Delete test clients afterwards from the client page (Admin only).

1. **Users** — Admin → Users: create one Manager, one Preparer and one Intake user. Sign in as each in a private window; confirm each is forced through two-factor enrollment and that the Admin receives a *new device* alert (Admin → Alerts, and Admin → Email outbox if SMTP is not configured).
2. **Client record** — create a client with an SSN, date of birth, spouse and a dependent. Check: SSN shows masked everywhere; Admin "Reveal" works and appears in the audit trail; the Intake user sees no SSN digits, notes or fee history; the Preparer sees the client only after being assigned.
3. **Edits and history** — change a phone number and add two year-history rows; confirm "years as client" updates and the audit trail lists the changed fields.
4. **Documents** — upload a PDF and an image from the client page; open the document, upload a second version, and download both versions. Set a status to *Rejected* with a reason and confirm it is required. In Supabase → Storage → `vault`, confirm the stored objects are unreadable binaries.
5. **Import** — upload a small CSV with a header row including one row missing a name and one with a 5-digit SSN; map columns; confirm the summary reports exactly those two failures and the others were created.
6. **Returning-client portal** — generate a link from the client page, open it in a private window, fail verification once, then verify with last-4 + date of birth; mark one section "No changes", update another, upload a document; confirm everything appears under *Client portal activity* on the record. Revoke the link and confirm the portal session ends.
7. **New-client intake** — generate an intake link, complete identity + form in a private window, confirm a client record was created with source *Website*, and that the link is now used.
8. **Sessions** — leave a staff session idle past the timeout (lower it in Admin → Settings to 1 minute first) and confirm you are signed out; revoke a test user from Admin → Users and confirm their open session dies immediately.
9. **Health and cron** — `/health` returns `ok`; after the first scheduled run, Vercel → Cron Jobs shows `/api/cron/cleanup` succeeding.

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

Coverage: first-admin bootstrap (closed without token, wrong token 404 + audit + rate limit, forced TOTP enrollment with QR/manual key/backup codes, closed once a user exists), /health reachability without secrets, login + mandatory MFA + backup codes, idle timeout and its admin setting, new-device alerts, revocation, lockout, CSRF, SSN encryption/masking/reveal audit, role isolation, edit audit, years-as-client, dependents, the full encrypted upload protocol (init → PUT to signed URL → complete, tamper and ownership checks, versions, download grants), CSV and Excel import with mapping and failure reporting, returning-client and new-client portal flows, the Storage adapter, envelope-encryption invariants, RLS on every table, cross-instance sessions / lockouts / rate limits, and the cron cleanup.

## Layout

```
api/index.js          Vercel serverless entry (imports the built app; friendly 503 if env is incomplete)
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
  routes/             setup (one-time bootstrap), health, auth, clients, documents, imports, admin, portal
  views/              EJS templates (plain, unstyled by design)
scripts/              gen-keys, create-user, db-migrate, storage-setup
tests/                node:test suites + fake Supabase Storage server
```
