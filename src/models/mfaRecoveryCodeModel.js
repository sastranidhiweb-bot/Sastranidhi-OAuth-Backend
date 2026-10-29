// src/models/mfaRecoveryCodeModel.js
const { MfaRecoveryCode } = require('../db/schemas');
const { toObjectId } = require('../utils/mongo');
const { sha256Hex } = require('../utils/crypto');

/** Replaces any existing recovery codes for a user with a fresh set -- called once, right after MFA setup is confirmed. */
async function replaceAllForUser(userId, rawCodes) {
  const user_id = toObjectId(userId);
  // Delete-then-insert rather than a transaction: MongoDB transactions
  // need a replica set, and a half-finished replace here only means the
  // user is shown codes that were already saved, never a wrong code.
  await MfaRecoveryCode.deleteMany({ user_id });
  await MfaRecoveryCode.insertMany(rawCodes.map((rawCode) => ({ user_id, code_hash: sha256Hex(rawCode) })));
}

/** Finds an unused recovery code by its raw value and marks it used in one step, so a code can never be used twice even under concurrent requests. */
async function consumeIfValid(userId, rawCode) {
  if (typeof rawCode !== 'string') return false;
  const consumed = await MfaRecoveryCode.findOneAndUpdate(
    { user_id: toObjectId(userId), code_hash: sha256Hex(rawCode), used_at: null },
    { $set: { used_at: new Date() } }
  ).lean();
  return Boolean(consumed);
}

async function countUnused(userId) {
  return MfaRecoveryCode.countDocuments({ user_id: toObjectId(userId), used_at: null });
}

async function deleteAllForUser(userId) {
  await MfaRecoveryCode.deleteMany({ user_id: toObjectId(userId) });
}

module.exports = { replaceAllForUser, consumeIfValid, countUnused, deleteAllForUser };
