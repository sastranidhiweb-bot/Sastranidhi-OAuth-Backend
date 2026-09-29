// src/models/passwordResetModel.js
const db = require('../config/db');

async function create({ userId, tokenHash, expiresAt }) {
  const result = await db.query(
    `INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (:userId, :tokenHash, :expiresAt)`,
    { userId, tokenHash, expiresAt }
  );
  return result.insertId;
}

async function findValidByTokenHash(tokenHash) {
  const rows = await db.query(
    `SELECT * FROM password_resets
     WHERE token_hash = :tokenHash AND used_at IS NULL AND expires_at > NOW()
     LIMIT 1`,
    { tokenHash }
  );
  return rows[0] || null;
}

async function markUsed(id) {
  await db.query('UPDATE password_resets SET used_at = NOW() WHERE id = :id', { id });
}

/** Invalidates any other still-live reset tokens for this user once one is successfully used — a stale, unused token from an earlier request shouldn't remain redeemable. */
async function invalidateAllForUser(userId) {
  await db.query(
    'UPDATE password_resets SET used_at = NOW() WHERE user_id = :userId AND used_at IS NULL',
    { userId }
  );
}

module.exports = { create, findValidByTokenHash, markUsed, invalidateAllForUser };
