import nodemailer from 'nodemailer';
import type { DB } from '../lib/db.js';
import type { AppConfig } from '../config.js';
import { newId } from '../lib/crypto.js';

export interface SendOutcome {
  id: string;
  status: 'queued' | 'sent' | 'failed';
  error?: string;
}
export interface Mailer {
  /** True when SMTP settings are present; false means outbox-only mode. */
  readonly configured: boolean;
  /** Records the message in the outbox and, when configured, delivers it inline. Never throws. */
  send(to: string, subject: string, body: string): Promise<SendOutcome>;
  /** Re-attempts delivery of an outbox row (Admin → Outbox → Retry). */
  retry(id: string): Promise<SendOutcome>;
  /** Sends a short test message and reports the exact SMTP error on failure. */
  sendTest(to: string): Promise<{ ok: boolean; error?: string }>;
}

export interface OutboxRow {
  id: string;
  ts: string;
  to_addr: string;
  subject: string;
  body: string;
  status: 'queued' | 'sent' | 'failed';
  attempts: number;
  last_error: string | null;
  sent_at: string | null;
}

// Serverless: deliver inline with tight timeouts so a slow SMTP host cannot stall a request.
const SMTP_TIMEOUT_MS = 8_000;
const MAX_ERROR_LEN = 500;

/** Strips anything that could be a credential from an SMTP error before it is stored or shown. */
export function sanitizeSmtpError(err: unknown, cfg?: AppConfig['smtp']): string {
  let msg = err instanceof Error ? `${(err as any).code ? (err as any).code + ': ' : ''}${err.message}` : String(err);
  if (cfg?.pass) msg = msg.split(cfg.pass).join('[redacted]');
  if (cfg?.user) msg = msg.split(cfg.user).join('[smtp user]');
  msg = msg.replace(/AUTH PLAIN \S+/gi, 'AUTH PLAIN [redacted]').replace(/(password|pass)=\S+/gi, '$1=[redacted]');
  return msg.slice(0, MAX_ERROR_LEN);
}

export function createMailer(db: DB, config: AppConfig): Mailer {
  const smtp = config.smtp;
  const transport = smtp
    ? nodemailer.createTransport({
        host: smtp.host,
        port: smtp.port,
        secure: smtp.secure,
        auth: smtp.user ? { user: smtp.user, pass: smtp.pass } : undefined,
        connectionTimeout: SMTP_TIMEOUT_MS,
        greetingTimeout: SMTP_TIMEOUT_MS,
        socketTimeout: SMTP_TIMEOUT_MS,
        logger: false,
      })
    : null;

  async function deliver(row: Pick<OutboxRow, 'id' | 'to_addr' | 'subject' | 'body'>): Promise<SendOutcome> {
    if (!transport) return { id: row.id, status: 'queued' };
    try {
      await transport.sendMail({ from: smtp!.from, to: row.to_addr, subject: row.subject, text: row.body });
      await db.run(`UPDATE email_outbox SET status = 'sent', attempts = attempts + 1, last_error = NULL, sent_at = now() WHERE id = ?`, row.id);
      return { id: row.id, status: 'sent' };
    } catch (err) {
      const error = sanitizeSmtpError(err, smtp);
      await db.run(`UPDATE email_outbox SET status = 'failed', attempts = attempts + 1, last_error = ? WHERE id = ?`, error, row.id);
      return { id: row.id, status: 'failed', error };
    }
  }

  return {
    configured: !!transport,
    async send(to, subject, body) {
      const id = newId();
      await db.run('INSERT INTO email_outbox (id, to_addr, subject, body, status) VALUES (?, ?, ?, ?, ?)', id, to, subject, body, 'queued');
      return deliver({ id, to_addr: to, subject, body });
    },
    async retry(id) {
      const row = await db.one<OutboxRow>('SELECT * FROM email_outbox WHERE id = ?', id);
      if (!row) throw new Error('Message not found');
      if (!transport) return { id, status: 'queued', error: 'Email is not configured' };
      return deliver(row);
    },
    async sendTest(to) {
      if (!transport) return { ok: false, error: 'Email is not configured (SMTP_HOST is not set).' };
      try {
        await transport.sendMail({ from: smtp!.from, to, subject: `[${'Taxonomy'}] Test email`, text: `This is a test message from the Taxonomy internal platform.\n\nSent ${new Date().toUTCString()} via ${smtp!.host}:${smtp!.port}.` });
        return { ok: true };
      } catch (err) {
        return { ok: false, error: sanitizeSmtpError(err, smtp) };
      }
    },
  };
}
