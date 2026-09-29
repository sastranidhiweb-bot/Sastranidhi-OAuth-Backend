// src/models/roleModel.js
const db = require('../config/db');

async function listAll() {
  const roles = await db.query('SELECT * FROM roles ORDER BY name');
  const permRows = await db.query(
    `SELECT rp.role_id, p.permission_code
     FROM role_permissions rp
     JOIN permissions p ON p.id = rp.permission_id`
  );

  const permsByRole = {};
  for (const row of permRows) {
    if (!permsByRole[row.role_id]) permsByRole[row.role_id] = [];
    permsByRole[row.role_id].push(row.permission_code);
  }

  return roles.map((role) => ({ ...role, permissions: permsByRole[role.id] || [] }));
}

async function findById(id) {
  const rows = await db.query('SELECT * FROM roles WHERE id = :id LIMIT 1', { id });
  if (!rows[0]) return null;

  const permRows = await db.query(
    `SELECT p.permission_code
     FROM role_permissions rp
     JOIN permissions p ON p.id = rp.permission_id
     WHERE rp.role_id = :id`,
    { id }
  );
  return { ...rows[0], permissions: permRows.map((r) => r.permission_code) };
}

async function findByName(name) {
  const rows = await db.query('SELECT * FROM roles WHERE name = :name LIMIT 1', { name });
  return rows[0] || null;
}

async function create({ name, description }) {
  const result = await db.query(
    'INSERT INTO roles (name, description) VALUES (:name, :description)',
    { name, description: description || null }
  );
  return findById(result.insertId);
}

async function update(id, { description }) {
  await db.query('UPDATE roles SET description = :description WHERE id = :id', {
    id,
    description: description || null,
  });
  return findById(id);
}

/** Cascades to role_permissions and user_roles via ON DELETE CASCADE. */
async function remove(id) {
  await db.query('DELETE FROM roles WHERE id = :id', { id });
}

async function addPermission(roleId, permissionCode) {
  await db.query(
    `INSERT IGNORE INTO role_permissions (role_id, permission_id)
     SELECT :roleId, id FROM permissions WHERE permission_code = :permissionCode`,
    { roleId, permissionCode }
  );
}

async function removePermission(roleId, permissionCode) {
  await db.query(
    `DELETE rp FROM role_permissions rp
     JOIN permissions p ON p.id = rp.permission_id
     WHERE rp.role_id = :roleId AND p.permission_code = :permissionCode`,
    { roleId, permissionCode }
  );
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
