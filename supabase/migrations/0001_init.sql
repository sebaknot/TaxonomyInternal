-- Taxonomy Internal: Build 1 schema (Postgres / Supabase).
-- All data access goes through the application server using the service role / postgres
-- connection. Row Level Security is enabled on every table with NO policies, so the Supabase
-- anon/authenticated API roles can read nothing.

CREATE TABLE settings (
  key text PRIMARY KEY,
  value text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id uuid PRIMARY KEY,
  email text NOT NULL,
  name text NOT NULL,
  role text NOT NULL CHECK (role IN ('admin','manager','preparer','intake','bookkeeper')),
  password_hash text NOT NULL,
  mfa_secret_enc text,
  mfa_enabled boolean NOT NULL DEFAULT false,
  backup_codes text,
  is_active boolean NOT NULL DEFAULT true,
  revoked_at timestamptz,
  revoked_by uuid,
  failed_login_count integer NOT NULL DEFAULT 0,
  locked_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_lower_idx ON users (lower(email));

CREATE TABLE sessions (
  id text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token text NOT NULL,
  mfa_passed boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_activity_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  ip text,
  user_agent text,
  device_id text
);
CREATE INDEX sessions_user_idx ON sessions(user_id);

CREATE TABLE user_devices (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id text NOT NULL,
  user_agent text,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, device_id)
);
CREATE TABLE user_locations (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ip text NOT NULL,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, ip)
);

-- Login / MFA / portal throttling, shared across serverless instances.
CREATE TABLE rate_limits (
  key text PRIMARY KEY,
  window_start timestamptz NOT NULL,
  count integer NOT NULL DEFAULT 0
);

CREATE TABLE audit_log (
  id bigserial PRIMARY KEY,
  ts timestamptz NOT NULL DEFAULT now(),
  actor_type text NOT NULL CHECK (actor_type IN ('user','client','system','anonymous')),
  actor_id text,
  actor_label text,
  action text NOT NULL,
  entity_type text,
  entity_id text,
  client_id uuid,
  details jsonb,
  ip text,
  user_agent text
);
CREATE INDEX audit_ts_idx ON audit_log(ts);
CREATE INDEX audit_client_idx ON audit_log(client_id, ts);
CREATE INDEX audit_action_idx ON audit_log(action, ts);

CREATE TABLE admin_alerts (
  id uuid PRIMARY KEY,
  ts timestamptz NOT NULL DEFAULT now(),
  type text NOT NULL,
  user_id uuid,
  message text NOT NULL,
  details text,
  acknowledged_at timestamptz,
  acknowledged_by text
);

CREATE TABLE email_outbox (
  id uuid PRIMARY KEY,
  ts timestamptz NOT NULL DEFAULT now(),
  to_addr text NOT NULL,
  subject text NOT NULL,
  body text NOT NULL,
  sent_at timestamptz,
  error text
);

CREATE TABLE clients (
  id uuid PRIMARY KEY,
  legal_name text NOT NULL,
  preferred_name text,
  ssn_enc text,
  ssn_last4 text,
  dob date,
  phone text,
  email text,
  address_line1 text,
  address_line2 text,
  city text,
  state text,
  zip text,
  filing_status text,
  spouse_name text,
  spouse_ssn_enc text,
  spouse_ssn_last4 text,
  spouse_dob date,
  assigned_preparer_id uuid REFERENCES users(id) ON DELETE SET NULL,
  source text,
  notes text,
  client_since_year integer,
  status text NOT NULL DEFAULT 'active',
  created_by uuid,
  created_via text NOT NULL DEFAULT 'staff',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX clients_name_idx ON clients(legal_name);
CREATE INDEX clients_preparer_idx ON clients(assigned_preparer_id);

CREATE TABLE dependents (
  id uuid PRIMARY KEY,
  client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  name text NOT NULL,
  relationship text,
  dob date,
  ssn_enc text,
  ssn_last4 text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX dependents_client_idx ON dependents(client_id);

CREATE TABLE tags (
  id uuid PRIMARY KEY,
  name text NOT NULL
);
CREATE UNIQUE INDEX tags_name_lower_idx ON tags (lower(name));
CREATE TABLE client_tags (
  client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  tag_id uuid NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY (client_id, tag_id)
);

CREATE TABLE client_year_history (
  id uuid PRIMARY KEY,
  client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  year integer NOT NULL,
  services text,
  fee_cents integer,
  notes text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (client_id, year)
);

CREATE TABLE documents (
  id uuid PRIMARY KEY,
  client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  tax_year integer NOT NULL,
  category text NOT NULL,
  title text NOT NULL,
  status text NOT NULL DEFAULT 'uploaded' CHECK (status IN ('uploaded','reviewed','accepted','rejected')),
  rejection_reason text,
  status_set_by text,
  status_set_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX documents_client_idx ON documents(client_id, tax_year, category);

-- Each version is one object in Supabase Storage containing AES-256-GCM ciphertext produced in
-- the browser (or the server) with a per-version data key. The data key is itself encrypted with
-- the application master key (data_key_enc). Supabase never holds plaintext or a usable key.
CREATE TABLE document_versions (
  id uuid PRIMARY KEY,
  document_id uuid REFERENCES documents(id) ON DELETE CASCADE,   -- null while a brand-new upload is pending
  client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  version_no integer,
  original_filename text NOT NULL,
  storage_path text NOT NULL UNIQUE,
  size_bytes bigint,                 -- plaintext size, set on completion
  mime_type text,
  sha256 text,                       -- plaintext hash, reported by the uploader
  data_key_enc text NOT NULL,
  upload_state text NOT NULL DEFAULT 'pending' CHECK (upload_state IN ('pending','complete')),
  pending_meta jsonb,                -- {tax_year, category, title} for a pending new document
  uploaded_by_type text NOT NULL,
  uploaded_by_id text,
  uploaded_by_label text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  uploaded_at timestamptz,
  UNIQUE (document_id, version_no)
);
CREATE INDEX document_versions_doc_idx ON document_versions(document_id, version_no);
CREATE INDEX document_versions_pending_idx ON document_versions(upload_state, created_at);

CREATE TABLE magic_links (
  id uuid PRIMARY KEY,
  token_hash text NOT NULL UNIQUE,
  type text NOT NULL CHECK (type IN ('returning','intake')),
  client_id uuid REFERENCES clients(id) ON DELETE CASCADE,
  tax_year integer NOT NULL,
  label text,
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  verify_attempts integer NOT NULL DEFAULT 0,
  verified_at timestamptz,
  completed_at timestamptz,
  revoked_at timestamptz,
  created_client_id uuid
);

CREATE TABLE portal_sessions (
  id text PRIMARY KEY,
  magic_link_id uuid NOT NULL REFERENCES magic_links(id) ON DELETE CASCADE,
  client_id uuid,
  csrf_token text NOT NULL,
  verified boolean NOT NULL DEFAULT false,
  intake_identity text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_activity_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  ip text
);

CREATE TABLE imports (
  id uuid PRIMARY KEY,
  created_by uuid NOT NULL,
  original_filename text NOT NULL,
  storage_path text NOT NULL,
  data_key_enc text NOT NULL,
  headers text NOT NULL,
  row_count integer NOT NULL,
  mapping text,
  status text NOT NULL DEFAULT 'pending',
  summary text,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);

-- ---------- Row Level Security: on everywhere, no policies ----------
-- The application connects as the table owner (service role / postgres), which is not subject
-- to these policies. PostgREST roles (anon, authenticated) get nothing.
DO $$
DECLARE t text;
BEGIN
  FOR t IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
  END LOOP;
  -- Belt and braces on Supabase: strip the default grants from the API roles.
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon';
    EXECUTE 'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon';
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM authenticated';
    EXECUTE 'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM authenticated';
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM authenticated';
  END IF;
END $$;
