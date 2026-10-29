// src/models/passwordResetModel.js
const { PasswordReset } = require('../db/schemas');
const { toObjectId, toPlain } = require('../utils/mongo');

async function create({ userId, tokenHash, expiresAt }) {
  const reset = await PasswordReset.create({ user_id: toObjectId(userId), token_hash: tokenHash, expires_at: expiresAt });
  return String(reset._id);
}

async function findValidByTokenHash(tokenHash) {
  const reset = await PasswordReset.findOne({
    token_hash: tokenHash,
    used_at: null,
    expires_at: { $gt: new Date() },
  }).lean();
  return toPlain(reset);
}

async function markUsed(id) {
  await PasswordReset.updateOne({ _id: toObjectId(id) }, { $set: { used_at: new Date() } });
}

/** Invalidates any other still-live reset tokens for this user once one is successfully used — a stale, unused token from an earlier request shouldn't remain redeemable. */
async function invalidateAllForUser(userId) {
  await PasswordReset.updateMany({ user_id: toObjectId(userId), used_at: null }, { $set: { used_at: new Date() } });
}

module.exports = { create, findValidByTokenHash, markUsed, invalidateAllForUser };
