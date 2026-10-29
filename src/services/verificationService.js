// src/services/verificationService.js
//
// Handles the whole "prove you own this email address before you can
// register" flow. Deliberately service-owned, not trusted from the
// frontend: the only thing the frontend can hand back to /auth/register
// afterward is a short-lived, server-signed token (see stateToken) that
// says "this email was verified, recently, by us" — there's no
// `emailVerified: true` field anywhere the client could set to fake it.

const bcrypt = require('bcrypt');
const crypto = require('crypto');

const env = require('../config/env');
const emailVerificationModel = require('../models/emailVerificationModel');
const emailService = require('./emailService');
const stateToken = require('../utils/stateToken');
const ApiError = require('../utils/ApiError');
const normalizeEmail = require('../utils/normalizeEmail');

const CODE_LENGTH = 6;
const CODE_EXPIRES_MINUTES = 10;
const RESEND_COOLDOWN_SECONDS = 60;
const MAX_ATTEMPTS = 5;
// Bcrypt (not the fast sha256Hex used for opaque tokens elsewhere in this
// project) deliberately — a 6-digit code only has 1,000,000 possible
// values, so if this hash were ever exposed (e.g. a DB dump), a fast hash
// would make offline brute-forcing all million values close to instant.
// Slow, salted bcrypt keeps that infeasible even within the code's short
// lifetime.
const BCRYPT_ROUNDS = env.security.bcryptSaltRounds;

function generateCode() {
  // crypto.randomInt is a CSPRNG (unlike Math.random) — this is a
  // uniformly random integer in [0, 999999], zero-padded to 6 digits.
  return crypto.randomInt(0, 10 ** CODE_LENGTH).toString().padStart(CODE_LENGTH, '0');
}

/** Starts (or restarts) email verification for an address. Enforces the resend cooldown; the new code replaces any previous one (db/schemas.js: one live document per email). */
async function startVerification(email) {
  const existing = await emailVerificationModel.findByEmail(email);

  if (existing) {
    const secondsSinceLastSend = (Date.now() - new Date(existing.last_sent_at).getTime()) / 1000;
    if (secondsSinceLastSend < RESEND_COOLDOWN_SECONDS) {
      const retryAfterSeconds = Math.ceil(RESEND_COOLDOWN_SECONDS - secondsSinceLastSend);
      throw new ApiError(429, 'too_many_requests', `Please wait ${retryAfterSeconds}s before requesting another code.`, {
        retryAfterSeconds,
      });
    }
  }

  const code = generateCode();
  const codeHash = await bcrypt.hash(code, BCRYPT_ROUNDS);
  const expiresAt = new Date(Date.now() + CODE_EXPIRES_MINUTES * 60 * 1000);

  await emailVerificationModel.upsert({ email, codeHash, expiresAt, maxAttempts: MAX_ATTEMPTS });

  await emailService.send({
    to: email,
    subject: 'Your Sastranidhi verification code',
    text: `Your verification code is ${code}. It expires in ${CODE_EXPIRES_MINUTES} minutes. If you didn't request this, you can ignore this email.`,
  });

  return { expiresInMinutes: CODE_EXPIRES_MINUTES, resendCooldownSeconds: RESEND_COOLDOWN_SECONDS };
}

/** Verifies a submitted code. On success, returns a short-lived signed token proving verification — this is what /auth/register requires, not a boolean the frontend could forge. */
async function verifyCode(email, submittedCode) {
  const record = await emailVerificationModel.findByEmail(email);

  if (!record) {
    throw new ApiError(400, 'invalid_code', 'No verification code was requested for this email.');
  }
  if (record.verified_at) {
    // Idempotent: if they already verified (e.g. double-clicked), just
    // hand back a fresh proof token rather than erroring.
    return issueVerifiedToken(email);
  }
  if (new Date(record.expires_at) < new Date()) {
    throw new ApiError(400, 'code_expired', 'This verification code has expired. Please request a new one.');
  }
  if (record.attempt_count >= record.max_attempts) {
    throw new ApiError(429, 'too_many_attempts', 'Too many incorrect attempts. Please request a new code.');
  }

  const matches = await bcrypt.compare(String(submittedCode), record.code_hash);
  if (!matches) {
    await emailVerificationModel.incrementAttempts(email);
    const remaining = record.max_attempts - (record.attempt_count + 1);
    throw new ApiError(
      400,
      'invalid_code',
      remaining > 0 ? `Incorrect code. ${remaining} attempt(s) remaining.` : 'Incorrect code. No attempts remaining — please request a new code.'
    );
  }

  await emailVerificationModel.markVerified(email);
  return issueVerifiedToken(email);
}

function issueVerifiedToken(email) {
  // 15 minutes is enough to fill in the account-details step without the
  // proof going stale, but short enough that a leaked token (e.g. via a
  // shared/logged URL) is a narrow window, not a standing credential.
  const token = stateToken.sign({ purpose: 'email_verified', email: normalizeEmail(email) }, { expiresInSeconds: 15 * 60 });
  return { emailVerificationToken: token };
}

/** Used by POST /auth/register to confirm the token is real, unexpired, and for the exact email being registered. */
function assertEmailVerified(token, email) {
  const decoded = stateToken.verify(token);
  if (!decoded || decoded.purpose !== 'email_verified' || decoded.email !== normalizeEmail(email)) {
    throw new ApiError(400, 'email_not_verified', 'This email has not been verified, or the verification has expired. Please verify your email again.');
  }
}

module.exports = { startVerification, verifyCode, assertEmailVerified };
