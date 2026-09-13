import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';

export type DB = Database.Database;

const MIGRATIONS: string[] = [
  // 1 — foundation schema
  `
  CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin','manager','preparer','intake','bookkeeper')),
    password_hash TEXT NOT NULL,
    mfa_secret_enc TEXT,             -- encrypted TOTP secret (set during enrollment)
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    backup_codes TEXT,               -- JSON array of sha256 hashes of unused backup codes
    is_active INTEGER NOT NULL DEFAULT 1,
    revoked_at TEXT,
    revoked_by TEXT,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE sessions (
    id TEXT PRIMARY KEY,                  -- sha256 of the cookie token
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    mfa_passed INTEGER NOT NULL DEFAULT 0, -- 0 until the TOTP step succeeds
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_activity_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,             -- absolute lifetime
    ip TEXT,
    user_agent TEXT,
    device_id TEXT
  );
  CREATE INDEX idx_sessions_user ON sessions(user_id);

  CREATE TABLE user_devices (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    user_agent TEXT,
    first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, device_id)
  );
  CREATE TABLE user_locations (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, ip)
  );

  CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    actor_type TEXT NOT NULL CHECK (actor_type IN ('user','client','system','anonymous')),
    actor_id TEXT,
    actor_label TEXT,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id TEXT,
    client_id TEXT,                       -- denormalized so a client's record shows its own history
    details TEXT,                         -- JSON
    ip TEXT,
    user_agent TEXT
  );
  CREATE INDEX idx_audit_ts ON audit_log(ts);
  CREATE INDEX idx_audit_client ON audit_log(client_id, ts);
  CREATE INDEX idx_audit_action ON audit_log(action, ts);

  CREATE TABLE admin_alerts (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL DEFAULT (datetime('now')),
    type TEXT NOT NULL,
    user_id TEXT,
    message TEXT NOT NULL,
    details TEXT,
    acknowledged_at TEXT,
    acknowledged_by TEXT
  );

  CREATE TABLE email_outbox (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL DEFAULT (datetime('now')),
    to_addr TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    sent_at TEXT,
    error TEXT
  );

  CREATE TABLE clients (
    id TEXT PRIMARY KEY,
    legal_name TEXT NOT NULL,
    preferred_name TEXT,
    ssn_enc TEXT,
    ssn_last4 TEXT,
    dob TEXT,
    phone TEXT,
    email TEXT,
    address_line1 TEXT,
    address_line2 TEXT,
    city TEXT,
    state TEXT,
    zip TEXT,
    filing_status TEXT,
    spouse_name TEXT,
    spouse_ssn_enc TEXT,
    spouse_ssn_last4 TEXT,
    spouse_dob TEXT,
    assigned_preparer_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    source TEXT,
    notes TEXT,
    client_since_year INTEGER,            -- earliest known year; "years as client" derives from this
    status TEXT NOT NULL DEFAULT 'active',
    created_by TEXT,
    created_via TEXT NOT NULL DEFAULT 'staff', -- staff | import | portal_intake
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX idx_clients_name ON clients(legal_name);
  CREATE INDEX idx_clients_preparer ON clients(assigned_preparer_id);

  CREATE TABLE dependents (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    relationship TEXT,
    dob TEXT,
    ssn_enc TEXT,
    ssn_last4 TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX idx_dependents_client ON dependents(client_id);

  CREATE TABLE tags (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE
  );
  CREATE TABLE client_tags (
    client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    tag_id TEXT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, tag_id)
  );

  CREATE TABLE client_year_history (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    year INTEGER NOT NULL,
    services TEXT,
    fee_cents INTEGER,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (client_id, year)
  );

  CREATE TABLE documents (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    tax_year INTEGER NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,                  -- logical name (defaults to first uploaded filename)
    status TEXT NOT NULL DEFAULT 'uploaded' CHECK (status IN ('uploaded','reviewed','accepted','rejected')),
    rejection_reason TEXT,
    status_set_by TEXT,
    status_set_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX idx_documents_client ON documents(client_id, tax_year, category);

  CREATE TABLE document_versions (
    id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    version_no INTEGER NOT NULL,
    original_filename TEXT NOT NULL,
    stored_name TEXT NOT NULL,            -- random name under uploads/, content is AES-GCM encrypted
    size_bytes INTEGER NOT NULL,
    mime_type TEXT,
    sha256 TEXT NOT NULL,
    iv TEXT NOT NULL,
    auth_tag TEXT NOT NULL,
    uploaded_by_type TEXT NOT NULL,       -- user | client
    uploaded_by_id TEXT,
    uploaded_by_label TEXT NOT NULL,
    uploaded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (document_id, version_no)
  );

  CREATE TABLE magic_links (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL CHECK (type IN ('returning','intake')),
    client_id TEXT REFERENCES clients(id) ON DELETE CASCADE,
    tax_year INTEGER NOT NULL,
    label TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    verify_attempts INTEGER NOT NULL DEFAULT 0,
    verified_at TEXT,
    completed_at TEXT,
    revoked_at TEXT,
    created_client_id TEXT
  );

  CREATE TABLE portal_sessions (
    id TEXT PRIMARY KEY,                  -- sha256 of cookie token
    magic_link_id TEXT NOT NULL REFERENCES magic_links(id) ON DELETE CASCADE,
    client_id TEXT,
    csrf_token TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    intake_identity TEXT,                 -- JSON {name,email,phone} for intake links
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_activity_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    ip TEXT
  );

  CREATE TABLE imports (
    id TEXT PRIMARY KEY,
    created_by TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    headers TEXT NOT NULL,                -- JSON string[]
    row_count INTEGER NOT NULL,
    mapping TEXT,                         -- JSON {header: field}
    status TEXT NOT NULL DEFAULT 'pending',
    summary TEXT,                         -- JSON {created, failed, errors:[{row, message}]}
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at TEXT
  );
  `,
];

export function openDatabase(dbPath: string): DB {
  if (dbPath !== ':memory:') fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  migrate(db);
  return db;
}

function migrate(db: DB) {
  db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')))`);
  const applied = new Set(db.prepare('SELECT version FROM schema_migrations').all().map((r: any) => r.version as number));
  MIGRATIONS.forEach((sql, i) => {
    const version = i + 1;
    if (applied.has(version)) return;
    db.transaction(() => {
      db.exec(sql);
      db.prepare('INSERT INTO schema_migrations (version) VALUES (?)').run(version);
    })();
  });
}

export function nowIso(): string {
  return new Date().toISOString();
}
