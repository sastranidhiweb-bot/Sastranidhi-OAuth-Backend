// src/models/refreshTokenModel.js
const db = require('../config/db');
const { sha256Hex } = require('../utils/crypto');

async function store({ userId, clientId, rawToken, scope, expiresAt }) {
  const tokenHash = sha256Hex(rawToken);
  await db.query(
    `INSERT INTO refresh_tokens (user_id, client_id, token_hash, scope, expires_at)
     VALUES (:userId, :clientId, :tokenHash, :scope, :expiresAt)`,
    { userId, clientId, tokenHash, scope: scope || null, expiresAt }
  );
}

async function findValidByRawToken(rawToken) {
  const tokenHash = sha256Hex(rawToken);
  const rows = await db.query(
    `SELECT * FROM refresh_tokens
     WHERE token_hash = :tokenHash AND revoked_at IS NULL AND expires_at > NOW()
     LIMIT 1`,
    { tokenHash }
  );
  return rows[0] || null;
}

async function revokeByRawToken(rawToken) {
  const tokenHash = sha256Hex(rawToken);
  await db.query('UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = :tokenHash', {
    tokenHash,
  });
}

async function revokeAllForUser(userId) {
  await db.query(
    'UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = :userId AND revoked_at IS NULL',
    { userId }
  );
}

module.exports = { store, findValidByRawToken, revokeByRawToken, revokeAllForUser };
