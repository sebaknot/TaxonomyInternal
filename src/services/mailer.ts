import nodemailer from 'nodemailer';
import type { DB } from '../lib/db.js';
import type { AppConfig } from '../config.js';
import { newId } from '../lib/crypto.js';

export interface Mailer {
  send(to: string, subject: string, body: string): Promise<void>;
}

/**
 * Sends via SMTP when configured. Every message is also recorded in email_outbox so
 * Admin can see what went out (and, without SMTP, can read magic links / alerts there).
 */
export function createMailer(db: DB, config: AppConfig): Mailer {
  const transport = config.smtp
    ? nodemailer.createTransport({
        host: config.smtp.host,
        port: config.smtp.port,
        secure: config.smtp.port === 465,
        auth: config.smtp.user ? { user: config.smtp.user, pass: config.smtp.pass } : undefined,
      })
    : null;
  return {
    async send(to, subject, body) {
      const id = newId();
      await db.run('INSERT INTO email_outbox (id, to_addr, subject, body) VALUES (?, ?, ?, ?)', id, to, subject, body);
      if (!transport) return;
      try {
        await transport.sendMail({ from: config.smtp!.from, to, subject, text: body });
        await db.run('UPDATE email_outbox SET sent_at = now() WHERE id = ?', id);
      } catch (err) {
        await db.run('UPDATE email_outbox SET error = ? WHERE id = ?', String(err), id);
      }
    },
  };
}
