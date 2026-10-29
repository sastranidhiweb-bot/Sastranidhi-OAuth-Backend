// src/models/emailVerificationModel.js
const { EmailVerification } = require('../db/schemas');
const { toPlain } = require('../utils/mongo');
const normalizeEmail = require('../utils/normalizeEmail');

async function findByEmail(email) {
  if (typeof email !== 'string') return null;
  return toPlain(await EmailVerification.findOne({ email: normalizeEmail(email) }).lean());
}

/** Creates a fresh document for this email, replacing any existing pending verification (one live code per email, see schemas.js). */
async function upsert({ email, codeHash, expiresAt, maxAttempts }) {
  await EmailVerification.updateOne(
    { email: normalizeEmail(email) },
    {
      $set: {
        code_hash: codeHash,
        attempt_count: 0,
        max_attempts: maxAttempts,
        last_sent_at: new Date(),
        expires_at: expiresAt,
        verified_at: null,
      },
    },
    { upsert: true }
  );
  return findByEmail(email);
}

async function incrementAttempts(email) {
  await EmailVerification.updateOne({ email: normalizeEmail(email) }, { $inc: { attempt_count: 1 } });
}

async function markVerified(email) {
  await EmailVerification.updateOne({ email: normalizeEmail(email) }, { $set: { verified_at: new Date() } });
}

module.exports = { findByEmail, upsert, incrementAttempts, markVerified };
