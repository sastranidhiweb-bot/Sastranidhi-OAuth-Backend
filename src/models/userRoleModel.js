// src/models/userRoleModel.js
const { UserRole, Role, Application } = require('../db/schemas');
const { toObjectId } = require('../utils/mongo');

/**
 * Returns { LMS: ['STUDENT'], PARIPRASHNA: ['TEACHER'], ... } for a user —
 * exactly the shape the architecture doc specifies for the JWT "apps" claim.
 * A user_roles document with application_id = null is a global role and is
 * attached under every active application.
 */
async function getRolesGroupedByApplication(userId) {
  const user_id = toObjectId(userId);
  if (!user_id) return {};

  const assignments = await UserRole.find({ user_id }).lean();
  if (assignments.length === 0) return {};

  const roles = await Role.find({ _id: { $in: assignments.map((a) => a.role_id) } }, { name: 1 }).lean();
  const roleNameById = new Map(roles.map((r) => [String(r._id), r.name]));

  const appIds = assignments.filter((a) => a.application_id).map((a) => a.application_id);
  const apps = await Application.find({ _id: { $in: appIds } }, { code: 1 }).lean();
  const appCodeById = new Map(apps.map((a) => [String(a._id), a.code]));

  const globalRoles = [];
  const grouped = {};
  for (const assignment of assignments) {
    const roleName = roleNameById.get(String(assignment.role_id));
    if (!roleName) continue;

    if (!assignment.application_id) {
      globalRoles.push(roleName);
      continue;
    }
    const appCode = appCodeById.get(String(assignment.application_id));
    if (!appCode) continue;
    if (!grouped[appCode]) grouped[appCode] = [];
    grouped[appCode].push(roleName);
  }

  if (globalRoles.length > 0) {
    const allApps = await Application.find({ is_active: true }, { code: 1 }).lean();
    for (const { code } of allApps) {
      grouped[code] = Array.from(new Set([...(grouped[code] || []), ...globalRoles]));
    }
  }

  return grouped;
}

/** Resolves role name + optional application code to ids; null if either doesn't exist. */
async function resolveAssignment({ roleName, applicationCode }) {
  const role = await Role.findOne({ name: roleName }, { _id: 1 }).lean();
  if (!role) return null;

  let applicationId = null;
  if (applicationCode) {
    const app = await Application.findOne({ code: applicationCode }, { _id: 1 }).lean();
    if (!app) return null;
    applicationId = app._id;
  }
  return { roleId: role._id, applicationId };
}

async function assignRole({ userId, roleName, applicationCode }) {
  const resolved = await resolveAssignment({ roleName, applicationCode });
  if (!resolved) return;

  // Upsert: re-assigning a role the user already has (same
  // user_id/role_id/application_id) is a no-op, not an error — the
  // unique index on user_roles would otherwise reject a duplicate.
  const assignment = { user_id: toObjectId(userId), role_id: resolved.roleId, application_id: resolved.applicationId };
  await UserRole.updateOne(assignment, { $setOnInsert: assignment }, { upsert: true });
}

async function removeRole({ userId, roleName, applicationCode }) {
  const resolved = await resolveAssignment({ roleName, applicationCode });
  if (!resolved) return;

  await UserRole.deleteMany({
    user_id: toObjectId(userId),
    role_id: resolved.roleId,
    application_id: resolved.applicationId,
  });
}

/** Flat list of role assignments for one user, for admin display (not grouped like the JWT claim). */
async function listForUser(userId) {
  const assignments = await UserRole.find({ user_id: toObjectId(userId) }).lean();

  const roles = await Role.find({ _id: { $in: assignments.map((a) => a.role_id) } }, { name: 1 }).lean();
  const roleNameById = new Map(roles.map((r) => [String(r._id), r.name]));
  const apps = await Application.find(
    { _id: { $in: assignments.filter((a) => a.application_id).map((a) => a.application_id) } },
    { code: 1 }
  ).lean();
  const appCodeById = new Map(apps.map((a) => [String(a._id), a.code]));

  return assignments
    .filter((a) => roleNameById.has(String(a.role_id)))
    .map((a) => ({
      id: String(a._id),
      role_name: roleNameById.get(String(a.role_id)),
      application_code: a.application_id ? appCodeById.get(String(a.application_id)) || null : null,
      created_at: a.created_at,
    }))
    .sort((x, y) => x.role_name.localeCompare(y.role_name));
}

module.exports = { getRolesGroupedByApplication, assignRole, removeRole, listForUser };
