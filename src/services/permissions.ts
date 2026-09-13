import type { Role } from '../lib/constants.js';

export interface SessionUser {
  id: string;
  email: string;
  name: string;
  role: Role;
}

/**
 * Central permission policy. Every route check goes through here so the role matrix
 * lives in one place.
 */
export const can = {
  manageUsers: (u: SessionUser) => u.role === 'admin',
  viewAuditLog: (u: SessionUser) => u.role === 'admin',
  manageSettings: (u: SessionUser) => u.role === 'admin',
  revealSsn: (u: SessionUser) => u.role === 'admin',
  /** Sees masked last-4. Intake staff see no digits at all. */
  seeSsnLast4: (u: SessionUser) => u.role !== 'intake',
  seeSensitiveFields: (u: SessionUser) => u.role !== 'intake', // internal notes, fee history, full DOB
  accessClients: (u: SessionUser) => ['admin', 'manager', 'preparer', 'intake'].includes(u.role),
  /** Full client list (not just assigned). */
  viewAllClients: (u: SessionUser) => ['admin', 'manager', 'intake'].includes(u.role),
  createClients: (u: SessionUser) => ['admin', 'manager', 'intake'].includes(u.role),
  editClientCore: (u: SessionUser) => ['admin', 'manager', 'preparer', 'intake'].includes(u.role),
  editClientSensitive: (u: SessionUser) => ['admin', 'manager', 'preparer'].includes(u.role),
  deleteClients: (u: SessionUser) => u.role === 'admin',
  assignPreparer: (u: SessionUser) => ['admin', 'manager'].includes(u.role),
  bulkImport: (u: SessionUser) => ['admin', 'manager'].includes(u.role),
  uploadDocuments: (u: SessionUser) => ['admin', 'manager', 'preparer', 'intake'].includes(u.role),
  downloadDocuments: (u: SessionUser) => ['admin', 'manager', 'preparer', 'intake'].includes(u.role),
  setDocumentStatus: (u: SessionUser) => ['admin', 'manager', 'preparer'].includes(u.role),
  generateMagicLinks: (u: SessionUser) => ['admin', 'manager', 'preparer', 'intake'].includes(u.role),
  manageTags: (u: SessionUser) => ['admin', 'manager'].includes(u.role),
};

/** Whether this user may see a given client record. */
export function canAccessClient(u: SessionUser, client: { assigned_preparer_id: string | null }): boolean {
  if (!can.accessClients(u)) return false;
  if (can.viewAllClients(u)) return true;
  if (u.role === 'preparer') return client.assigned_preparer_id === u.id;
  return false;
}
