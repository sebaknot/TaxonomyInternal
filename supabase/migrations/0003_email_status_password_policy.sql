-- Outbox becomes a delivery log: queued -> sent | failed, with retry bookkeeping.
ALTER TABLE email_outbox
  ADD COLUMN status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','sent','failed')),
  ADD COLUMN attempts integer NOT NULL DEFAULT 0,
  ADD COLUMN last_error text;
UPDATE email_outbox SET status = 'sent', attempts = 1 WHERE sent_at IS NOT NULL;
UPDATE email_outbox SET status = 'failed', attempts = 1, last_error = error WHERE sent_at IS NULL AND error IS NOT NULL;
ALTER TABLE email_outbox DROP COLUMN error;
CREATE INDEX email_outbox_status_idx ON email_outbox(status, ts);

-- Admin-created users and admin password resets must change their password at first sign-in.
ALTER TABLE users ADD COLUMN must_change_password boolean NOT NULL DEFAULT false;
