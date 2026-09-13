import type { AppContext } from '../context.js';
import { SETTING_DEFAULTS } from '../lib/constants.js';

export function getSetting(ctx: AppContext, key: string): string {
  const row = ctx.db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as { value: string } | undefined;
  return row?.value ?? SETTING_DEFAULTS[key] ?? '';
}
export function getSettingInt(ctx: AppContext, key: string): number {
  const n = parseInt(getSetting(ctx, key), 10);
  return Number.isFinite(n) ? n : parseInt(SETTING_DEFAULTS[key] ?? '0', 10);
}
export function setSetting(ctx: AppContext, key: string, value: string): void {
  ctx.db
    .prepare(
      `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`,
    )
    .run(key, value);
}
export function allSettings(ctx: AppContext): Record<string, string> {
  const out: Record<string, string> = { ...SETTING_DEFAULTS };
  for (const r of ctx.db.prepare('SELECT key, value FROM settings').all() as { key: string; value: string }[]) out[r.key] = r.value;
  return out;
}
