# Taxonomy Internal Platform — Build 1: Foundation

Internal tax-practice management platform for Taxonomy. This build delivers the secure foundation:

- **Authentication & roles** — five roles (Owner/Admin, Manager, Tax Preparer, Intake Staff, Bookkeeper), mandatory TOTP two-factor authentication, configurable idle timeout (default 15 min), new-device / new-location admin alerts, instant per-user revocation, and a full audit log of every login, logout and failed attempt.
- **Client records** — encrypted SSNs (AES-256-GCM at rest, masked as `***-**-1234` everywhere; Admin can reveal with an explicit, audited action), dependents, spouse, filing status, assigned preparer, specialization tags, source, notes, year-by-year history, auto-calculated years as client. Every edit is audited with the changed fields.
- **Bulk import** — CSV / Excel (TaxWise-style export) with per-column mapping and a created/failed summary with per-row reasons.
- **Document vault** — organized by tax year → category; every upload records uploader, timestamp, filename, year, category; staff-settable status (Uploaded / Reviewed / Accepted / Rejected + reason); re-uploads create a new version and never overwrite; files are encrypted at rest.
- **Client portal (magic links)** — returning-client links gated by last-4 SSN + date of birth, with "No changes" / "Update" per section and document upload straight into the vault; new-client intake links with an identity step then a full intake form that creates the record. Every client action is logged and shown on the client record.

Not in this build (by design): engagement letters / e-sign, payments, pipeline dashboard, calendar, visual design, OCR, SMS. The UI is intentionally plain.

## Stack

Node.js 22 · TypeScript · Express 5 · SQLite (better-sqlite3, WAL) · server-rendered EJS · no frontend framework. No external services are required; SMTP is optional.

## Setup

```bash
npm install
npm run gen-keys            # prints APP_ENCRYPTION_KEY and SESSION_SECRET
cp .env.example .env        # paste the keys in; set BASE_URL to the public URL
npm run create-user -- --email you@firm.com --name "Your Name" --role admin --password 'a-strong-passphrase-1'
npm run dev                 # http://localhost:3000
```

On first sign-in every user is forced to enroll an authenticator app (Google Authenticator, 1Password, Authy…). Eight one-time backup codes are shown once.

### Production notes

- Serve over HTTPS and set `COOKIE_SECURE=true` (the app refuses to start in production without it). Set `TRUST_PROXY=true` behind a reverse proxy so IP-based alerts see the real client address.
- `APP_ENCRYPTION_KEY` encrypts SSNs, MFA secrets and every uploaded file. **Back it up separately from the database; without it the data is unrecoverable.** Never rotate it casually.
- `DATA_DIR` holds the SQLite database and encrypted uploads. Back it up (the database uses WAL; copy `taxonomy.sqlite*` together or use `sqlite3 .backup`).
- Configure `SMTP_*` so security alerts and portal links are actually emailed. Without SMTP every outgoing message is recorded in **Admin → Email outbox** (useful for testing).
- Build for deployment: `npm run build` then `npm start`.

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

- Passwords: scrypt (N=2^15) with per-user salt; 12-char minimum; lockout for 15 min after 5 failures; login/MFA/portal endpoints rate-limited per IP.
- Sessions: random 256-bit token stored hashed; `HttpOnly`, `SameSite=Lax` cookies; idle timeout (admin-configurable) + 12-hour absolute lifetime; per-session CSRF token on every state-changing request.
- MFA: RFC 6238 TOTP (secret encrypted at rest) + hashed one-time backup codes; a password-only session can reach nothing but the MFA step.
- Revocation: deactivating a user deletes all their sessions immediately; every request re-checks the user is still active.
- Alerts: a signed device cookie and the source IP are compared with the user's known devices/IPs; unknown ones create an alert in Admin → Alerts and email all admins.
- Encryption at rest: AES-256-GCM with per-record AAD for SSNs (client, spouse, dependents) and MFA secrets; uploaded files are streamed through AES-256-GCM and stored under random names. Downloads are served as attachments with `nosniff`.
- Magic links: 256-bit tokens stored hashed, expire after a configurable number of hours (default 72), locked after 5 failed verifications, revocable by staff, shown to staff only once.
- Headers: Helmet CSP (`default-src 'self'`), no-referrer, `Cache-Control: no-store` on every response, HSTS when HTTPS is enabled.
- Audit log: append-only table capturing actor, action, entity, client, details, IP and user agent — Admin → Audit log, and per client at `/clients/:id/audit`.

## Tests

```bash
npm test          # node:test via tsx; each file boots an isolated app on a temp SQLite DB
npm run typecheck
```

Coverage: login + mandatory MFA + backup codes, idle timeout and its admin setting, new-device alerts, revocation, lockout, CSRF, SSN encryption/masking/reveal audit, role isolation, edit audit, years-as-client, dependents, document upload/versions/encrypted storage/download/status, CSV and Excel import with mapping and failure reporting, returning-client and new-client portal flows.

## Layout

```
src/
  app.ts            express app factory (createContext / createApp)
  server.ts         entrypoint
  config.ts         env config (fails fast on missing keys)
  lib/              db schema + migrations, crypto, TOTP, upload helpers, constants
  services/         auth, permissions, clients, documents, imports, magic links, audit, settings, mailer
  routes/           auth, clients, documents, imports, admin, portal
  views/            EJS templates (plain, unstyled by design)
  public/           minimal CSS/JS
scripts/            gen-keys, create-user
tests/              node:test suites
```
