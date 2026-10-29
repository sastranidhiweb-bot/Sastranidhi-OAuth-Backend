// src/models/roleModel.js
const { Role, Permission, UserRole } = require('../db/schemas');
const { toObjectId, toPlain } = require('../utils/mongo');

/** Roles are returned with `permissions` as a sorted list of permission codes, the same shape the SQL version built from role_permissions. */
function withSortedPermissions(role) {
  const plain = toPlain(role);
  if (plain) plain.permissions = [...(plain.permissions || [])].sort();
  return plain;
}

async function listAll() {
  const roles = await Role.find().sort({ name: 1 }).lean();
  return roles.map(withSortedPermissions);
}

async function findById(id) {
  const _id = toObjectId(id);
  if (!_id) return null;
  return withSortedPermissions(await Role.findById(_id).lean());
}

async function findByName(name) {
  if (typeof name !== 'string') return null;
  return withSortedPermissions(await Role.findOne({ name }).lean());
}

async function create({ name, description }) {
  const role = await Role.create({ name, description: description || null });
  return findById(role._id);
}

async function update(id, { description }) {
  await Role.updateOne({ _id: toObjectId(id) }, { $set: { description: description || null } });
  return findById(id);
}

/** Also removes every user_roles assignment of this role (what ON DELETE CASCADE did in MySQL). */
async function remove(id) {
  const _id = toObjectId(id);
  if (!_id) return;
  await UserRole.deleteMany({ role_id: _id });
  await Role.deleteOne({ _id });
}

/** No-op if the permission code doesn't exist or the role already has it. */
async function addPermission(roleId, permissionCode) {
  if (!(await Permission.exists({ permission_code: permissionCode }))) return;
  await Role.updateOne({ _id: toObjectId(roleId) }, { $addToSet: { permissions: permissionCode } });
}

async function removePermission(roleId, permissionCode) {
  await Role.updateOne({ _id: toObjectId(roleId) }, { $pull: { permissions: permissionCode } });
}

module.exports = {
  listAll,
  findById,
  findByName,
  create,
  update,
  remove,
  addPermission,
  removePermission,
};
