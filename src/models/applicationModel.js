// src/models/applicationModel.js
const { Application } = require('../db/schemas');
const { toObjectId, toPlain } = require('../utils/mongo');

async function findByCode(code) {
  if (typeof code !== 'string') return null;
  return toPlain(await Application.findOne({ code }).lean());
}

async function findById(id) {
  const _id = toObjectId(id);
  if (!_id) return null;
  return toPlain(await Application.findById(_id).lean());
}

async function listActive() {
  const rows = await Application.find({ is_active: true }).lean();
  return rows.map(toPlain);
}

module.exports = { findByCode, findById, listActive };
