// src/models/permissionModel.js
const db = require('../config/db');

async function listAll() {
  return db.query('SELECT * FROM permissions ORDER BY permission_code');
}

async function findByCode(code) {
  const rows = await db.query(
    'SELECT * FROM permissions WHERE permission_code = :code LIMIT 1',
    { code }
  );
  return rows[0] || null;
}

/**
 * Global permissions are what gate the Admin API -- deliberately scoped to
 * user_roles rows with application_id IS NULL. A role assigned *within* an
 * application (e.g. "ADMIN" scoped to LMS) grants admin rights inside that
 * child app's own domain, not over this Identity Provider itself. Only a
 * globally-assigned role administers the IdP.
 *
 * (An earlier version of this file checked ANY role regardless of
 * application scope, which would have let an LMS-scoped TEACHER -- who has
 * courses.manage within LMS -- also pass admin checks on this server. That
 * was a real privilege-scoping bug, fixed by the application_id IS NULL
 * filter below.)
 *
 * This is looked up fresh from the database on every admin request rather
 * than trusted from the access token's "apps" claim -- a role change should
 * take effect on the next request, not wait out the token's 15-minute
 * lifetime.
 */
async function getGlobalPermissionCodesForUser(userId) {
  const rows = await db.query(
    `SELECT DISTINCT p.permission_code
     FROM user_roles ur
     JOIN role_permissions rp ON rp.role_id = ur.role_id
     JOIN permissions p ON p.id = rp.permission_id
     WHERE ur.user_id = :userId AND ur.application_id IS NULL`,
    { userId }
  );
  return rows.map((r) => r.permission_code);
}

module.exports = { listAll, findByCode, getGlobalPermissionCodesForUser };
