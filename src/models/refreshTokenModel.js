// src/models/refreshTokenModel.js
const { RefreshToken } = require('../db/schemas');
const { toObjectId, toPlain } = require('../utils/mongo');
const { sha256Hex } = require('../utils/crypto');

async function store({ userId, clientId, rawToken, scope, expiresAt }) {
  await RefreshToken.create({
    user_id: toObjectId(userId),
    client_id: clientId,
    token_hash: sha256Hex(rawToken),
    scope: scope || null,
    expires_at: expiresAt,
  });
}

async function findValidByRawToken(rawToken) {
  if (typeof rawToken !== 'string') return null;
  const token = await RefreshToken.findOne({
    token_hash: sha256Hex(rawToken),
    revoked_at: null,
    expires_at: { $gt: new Date() },
  }).lean();
  return toPlain(token);
}

async function revokeByRawToken(rawToken) {
  if (typeof rawToken !== 'string') return;
  await RefreshToken.updateMany({ token_hash: sha256Hex(rawToken) }, { $set: { revoked_at: new Date() } });
}

async function revokeAllForUser(userId) {
  await RefreshToken.updateMany({ user_id: toObjectId(userId), revoked_at: null }, { $set: { revoked_at: new Date() } });
}

module.exports = { store, findValidByRawToken, revokeByRawToken, revokeAllForUser };
