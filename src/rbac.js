'use strict';
/** Role-based access control for admin users (least privilege). */

const ROLE_PERMISSIONS = {
  SUPER_ADMIN: ['*'],
  PROGRAM_MANAGER: [
    'dashboard.view', 'farmers.view', 'farmers.block', 'farmers.adjust',
    'products.manage', 'batches.manage', 'qr.view', 'qr.generate', 'qr.block', 'qr.export',
    'rewards.manage', 'wholesalers.manage', 'reports.view', 'audit.view', 'reviews.manage',
    'redemptions.view', 'redemptions.cancel',
  ],
  OPERATIONS: [
    'dashboard.view', 'farmers.view', 'batches.manage',
    'qr.view', 'qr.generate', 'qr.block', 'qr.export', 'reviews.manage', 'redemptions.view',
  ],
  REPORT_VIEWER: ['dashboard.view', 'reports.view', 'farmers.view', 'audit.view', 'redemptions.view'],
  SUPPORT: ['dashboard.view', 'farmers.view', 'farmers.block', 'reviews.manage', 'redemptions.view', 'redemptions.cancel'],
};

// Assignable staff roles (WHOLESALER accounts are managed in the Wholesalers section).
const STAFF_ROLES = ['SUPER_ADMIN', 'PROGRAM_MANAGER', 'OPERATIONS', 'SUPPORT', 'REPORT_VIEWER'];

function permissionsFor(role) { return ROLE_PERMISSIONS[role] || []; }

function hasPermission(role, perm) {
  const perms = permissionsFor(role);
  return perms.includes('*') || perms.includes(perm);
}

/** Express middleware factory: require a specific permission on the session's admin role. */
function requirePermission(perm) {
  return (req, res, next) => {
    const u = req.session.user;
    if (!u || u.role !== 'admin') return res.status(401).json({ error: 'unauthorized' });
    if (!hasPermission(u.adminRole, perm)) {
      const { audit } = require('./db');
      audit({ role: 'admin', id: u.id, action: 'permission_denied', entity: perm,
        severity: 'warning', ip: req.ip, requestId: req.requestId });
      return res.status(403).json({ error: 'forbidden' });
    }
    next();
  };
}

module.exports = { ROLE_PERMISSIONS, STAFF_ROLES, permissionsFor, hasPermission, requirePermission };
