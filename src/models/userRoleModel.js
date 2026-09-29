// src/models/userRoleModel.js
const db = require('../config/db');

/**
 * Returns { LMS: ['STUDENT'], PARIPRASHNA: ['TEACHER'], ... } for a user —
 * exactly the shape the architecture doc specifies for the JWT "apps" claim.
 * A user_roles row with application_id = NULL is a global role and is
 * attached under every active application.
 */
async function getRolesGroupedByApplication(userId) {
  const rows = await db.query(
    `SELECT a.code AS app_code, r.name AS role_name, ur.application_id
     FROM user_roles ur
     JOIN roles r ON r.id = ur.role_id
     LEFT JOIN applications a ON a.id = ur.application_id
     WHERE ur.user_id = :userId`,
    { userId }
  );

  const globalRoles = rows.filter((r) => r.application_id === null).map((r) => r.role_name);
  const scoped = rows.filter((r) => r.application_id !== null);

  const grouped = {};
  for (const row of scoped) {
    if (!grouped[row.app_code]) grouped[row.app_code] = [];
    grouped[row.app_code].push(row.role_name);
  }

  if (globalRoles.length > 0) {
    const allApps = await db.query('SELECT code FROM applications WHERE is_active = 1');
    for (const { code } of allApps) {
      grouped[code] = Array.from(new Set([...(grouped[code] || []), ...globalRoles]));
    }
  }

  return grouped;
}

async function assignRole({ userId, roleName, applicationCode }) {
  const params = { userId };
  let appJoin = '';
  if (applicationCode) {
    appJoin = 'AND a.code = :applicationCode';
    params.applicationCode = applicationCode;
  }

  // INSERT IGNORE: re-assigning a role the user already has (same
  // user_id/role_id/application_id) is a no-op, not an error — the
  // unique key on user_roles would otherwise throw ER_DUP_ENTRY.
  await db.query(
    `INSERT IGNORE INTO user_roles (user_id, role_id, application_id)
     SELECT :userId, r.id, ${applicationCode ? 'a.id' : 'NULL'}
     FROM roles r
     ${applicationCode ? 'JOIN applications a ON 1=1 ' + appJoin : ''}
     WHERE r.name = :roleName
     LIMIT 1`,
    { ...params, roleName }
  );
}

async function removeRole({ userId, roleName, applicationCode }) {
  const params = { userId, roleName };
  let appCondition = 'ur.application_id IS NULL';
  if (applicationCode) {
    appCondition = 'a.code = :applicationCode';
    params.applicationCode = applicationCode;
  }

  await db.query(
    `DELETE ur FROM user_roles ur
     JOIN roles r ON r.id = ur.role_id
     LEFT JOIN applications a ON a.id = ur.application_id
     WHERE ur.user_id = :userId AND r.name = :roleName AND ${appCondition}`,
    params
  );
}

/** Flat list of role assignments for one user, for admin display (not grouped like the JWT claim). */
async function listForUser(userId) {
  return db.query(
    `SELECT ur.id, r.name AS role_name, a.code AS application_code, ur.created_at
     FROM user_roles ur
     JOIN roles r ON r.id = ur.role_id
     LEFT JOIN applications a ON a.id = ur.application_id
     WHERE ur.user_id = :userId
     ORDER BY r.name`,
    { userId }
  );
}

module.exports = { getRolesGroupedByApplication, assignRole, removeRole, listForUser };
