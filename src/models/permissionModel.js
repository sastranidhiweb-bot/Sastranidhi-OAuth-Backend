// src/models/permissionModel.js
const { Permission, Role, UserRole } = require('../db/schemas');
const { toObjectId, toPlain } = require('../utils/mongo');

async function listAll() {
  const rows = await Permission.find().sort({ permission_code: 1 }).lean();
  return rows.map(toPlain);
}

async function findByCode(code) {
  if (typeof code !== 'string') return null;
  return toPlain(await Permission.findOne({ permission_code: code }).lean());
}

/**
 * Global permissions are what gate the Admin API -- deliberately scoped to
 * user_roles documents with application_id null. A role assigned *within*
 * an application (e.g. "ADMIN" scoped to LMS) grants admin rights inside
 * that child app's own domain, not over this Identity Provider itself.
 * Only a globally-assigned role administers the IdP.
 *
 * (An earlier version of this file checked ANY role regardless of
 * application scope, which would have let an LMS-scoped TEACHER -- who has
 * courses.manage within LMS -- also pass admin checks on this server. That
 * was a real privilege-scoping bug, fixed by the application_id null
 * filter below.)
 *
 * This is looked up fresh from the database on every admin request rather
 * than trusted from the access token's "apps" claim -- a role change should
 * take effect on the next request, not wait out the token's 15-minute
 * lifetime.
 */
async function getGlobalPermissionCodesForUser(userId) {
  const user_id = toObjectId(userId);
  if (!user_id) return [];

  const globalAssignments = await UserRole.find({ user_id, application_id: null }, { role_id: 1 }).lean();
  if (globalAssignments.length === 0) return [];

  const roles = await Role.find({ _id: { $in: globalAssignments.map((a) => a.role_id) } }, { permissions: 1 }).lean();
  return [...new Set(roles.flatMap((role) => role.permissions || []))];
}

module.exports = { listAll, findByCode, getGlobalPermissionCodesForUser };
