// src/models/applicationModel.js
const db = require('../config/db');

async function findByCode(code) {
  const rows = await db.query('SELECT * FROM applications WHERE code = :code LIMIT 1', { code });
  return rows[0] || null;
}

async function findById(id) {
  const rows = await db.query('SELECT * FROM applications WHERE id = :id LIMIT 1', { id });
  return rows[0] || null;
}

async function listActive() {
  return db.query('SELECT * FROM applications WHERE is_active = 1');
}

module.exports = { findByCode, findById, listActive };
