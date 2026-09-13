export const ROLES = ['admin', 'manager', 'preparer', 'intake', 'bookkeeper'] as const;
export type Role = (typeof ROLES)[number];
export const ROLE_LABELS: Record<Role, string> = {
  admin: 'Owner / Admin',
  manager: 'Manager',
  preparer: 'Tax Preparer',
  intake: 'Intake Staff',
  bookkeeper: 'Bookkeeper',
};

export const DOCUMENT_CATEGORIES = [
  'Personal Information',
  'W-2s',
  '1099s',
  'Business Income',
  'Business Expenses',
  'Mortgage/Property',
  'Investments',
  'Dependents',
  'Prior-Year Return',
  'IRS/State Notices',
  'Completed Return',
  'Engagement Letter',
  'Other',
] as const;
export type DocumentCategory = (typeof DOCUMENT_CATEGORIES)[number];

export const DOCUMENT_STATUSES = ['uploaded', 'reviewed', 'accepted', 'rejected'] as const;
export type DocumentStatus = (typeof DOCUMENT_STATUSES)[number];

export const FILING_STATUSES = [
  'Single',
  'Married Filing Jointly',
  'Married Filing Separately',
  'Head of Household',
  'Qualifying Surviving Spouse',
] as const;

export const CLIENT_SOURCES = ['Referral', 'Tax Prep', 'New', 'Website', 'Walk-in', 'Social Media', 'Other'] as const;

export const DEFAULT_TAGS = ['Real Estate', 'Crypto', 'Construction', 'Business Owner', 'International/Latin America'];

/** Settings keys (stored in the settings table, editable by Admin). */
export const SETTING_KEYS = {
  sessionIdleMinutes: 'session_idle_minutes',
  magicLinkHours: 'magic_link_valid_hours',
  currentTaxYear: 'current_tax_year',
  firmName: 'firm_name',
} as const;
export const SETTING_DEFAULTS: Record<string, string> = {
  session_idle_minutes: '15',
  magic_link_valid_hours: '72',
  current_tax_year: String(new Date().getFullYear() - 1),
  firm_name: 'Taxonomy',
};

export const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;
export const ALLOWED_UPLOAD_MIMES = new Set([
  'application/pdf',
  'image/jpeg',
  'image/png',
  'image/heic',
  'image/heif',
  'image/tiff',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'text/csv',
  'text/plain',
]);
export const ALLOWED_UPLOAD_EXTENSIONS = new Set([
  '.pdf', '.jpg', '.jpeg', '.png', '.heic', '.heif', '.tif', '.tiff', '.doc', '.docx', '.xls', '.xlsx', '.csv', '.txt',
]);
