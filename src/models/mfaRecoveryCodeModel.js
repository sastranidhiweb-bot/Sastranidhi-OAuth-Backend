// src/models/mfaRecoveryCodeModel.js
const db = require('../config/db');
const { sha256Hex } = require('../utils/crypto');

/** Replaces any existing recovery codes for a user with a fresh set -- called once, right after MFA setup is confirmed. */
async function replaceAllForUser(userId, rawCodes) {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    await conn.execute('DELETE FROM mfa_recovery_codes WHERE user_id = :userId', { userId });
    for (const rawCode of rawCodes) {
      await conn.execute(
        'INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES (:userId, :codeHash)',
        { userId, codeHash: sha256Hex(rawCode) }
      );
    }
    await conn.commit();
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

/** Finds an unused recovery code by its raw value and marks it used in one step, so a code can never be used twice even under concurrent requests. */
async function consumeIfValid(userId, rawCode) {
  const codeHash = sha256Hex(rawCode);
  const rows = await db.query(
    `UPDATE mfa_recovery_codes
     SET used_at = NOW()
     WHERE user_id = :userId AND code_hash = :codeHash AND used_at IS NULL
     LIMIT 1`,
    { userId, codeHash }
  );
  return rows.affectedRows === 1;
}

async function countUnused(userId) {
  const rows = await db.query(
    'SELECT COUNT(*) AS count FROM mfa_recovery_codes WHERE user_id = :userId AND used_at IS NULL',
    { userId }
  );
  return rows[0].count;
}

async function deleteAllForUser(userId) {
  await db.query('DELETE FROM mfa_recovery_codes WHERE user_id = :userId', { userId });
}

module.exports = { replaceAllForUser, consumeIfValid, countUnused, deleteAllForUser };
