// src/models/emailVerificationModel.js
const db = require('../config/db');

async function findByEmail(email) {
  const rows = await db.query('SELECT * FROM email_verifications WHERE email = :email LIMIT 1', {
    email,
  });
  return rows[0] || null;
}

/** Creates a fresh row for this email, replacing any existing pending verification (one live code per email, see schema.sql comment). */
async function upsert({ email, codeHash, expiresAt, maxAttempts }) {
  await db.query(
    `INSERT INTO email_verifications (email, code_hash, attempt_count, max_attempts, last_sent_at, expires_at, verified_at)
     VALUES (:email, :codeHash, 0, :maxAttempts, NOW(), :expiresAt, NULL)
     ON DUPLICATE KEY UPDATE
       code_hash = VALUES(code_hash),
       attempt_count = 0,
       max_attempts = VALUES(max_attempts),
       last_sent_at = NOW(),
       expires_at = VALUES(expires_at),
       verified_at = NULL`,
    { email, codeHash, expiresAt, maxAttempts }
  );
  return findByEmail(email);
}

async function incrementAttempts(email) {
  await db.query('UPDATE email_verifications SET attempt_count = attempt_count + 1 WHERE email = :email', {
    email,
  });
}

async function markVerified(email) {
  await db.query('UPDATE email_verifications SET verified_at = NOW() WHERE email = :email', { email });
}

module.exports = { findByEmail, upsert, incrementAttempts, markVerified };
