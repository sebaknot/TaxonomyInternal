import type { AppContext } from '../context.js';
import { SETTING_DEFAULTS } from '../lib/constants.js';

export async function allSettings(ctx: AppContext): Promise<Record<string, string>> {
  const out: Record<string, string> = { ...SETTING_DEFAULTS };
  for (const r of await ctx.db.all<{ key: string; value: string }>('SELECT key, value FROM settings')) out[r.key] = r.value;
  return out;
}
export async function getSetting(ctx: AppContext, key: string): Promise<string> {
  const row = await ctx.db.one<{ value: string }>('SELECT value FROM settings WHERE key = ?', key);
  return row?.value ?? SETTING_DEFAULTS[key] ?? '';
}
export async function getSettingInt(ctx: AppContext, key: string): Promise<number> {
  const n = parseInt(await getSetting(ctx, key), 10);
  return Number.isFinite(n) ? n : parseInt(SETTING_DEFAULTS[key] ?? '0', 10);
}
export async function setSetting(ctx: AppContext, key: string, value: string): Promise<void> {
  await ctx.db.run(
    `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, now())
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = now()`,
    key,
    value,
  );
}
