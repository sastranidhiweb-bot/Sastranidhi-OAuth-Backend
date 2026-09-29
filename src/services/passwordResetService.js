// src/services/passwordResetService.js

const bcrypt = require('bcrypt');
const env = require('../config/env');
const userModel = require('../models/userModel');
const passwordResetModel = require('../models/passwordResetModel');
const refreshTokenModel = require('../models/refreshTokenModel');
const emailService = require('./emailService');
const auditLogModel = require('../models/auditLogModel');
const ApiError = require('../utils/ApiError');
const { generateOpaqueToken, sha256Hex } = require('../utils/crypto');

const TOKEN_EXPIRES_MINUTES = 30;

/** Always resolves successfully regardless of whether the email exists — never let this endpoint be used to enumerate registered emails. */
async function requestReset(email) {
  const user = await userModel.findByEmail(email);
  if (!user) return;

  // Same opaque-token pattern as authorization codes / refresh tokens
  // (utils/crypto.js): 256 bits of randomness, stored as a fast SHA-256
  // hash rather than bcrypt — see that file's comment for why a fast hash
  // is fine for high-entropy tokens specifically (unlike the 6-digit
  // email verification code, which uses bcrypt for exactly the opposite
  // reason).
  const rawToken = generateOpaqueToken();
  const tokenHash = sha256Hex(rawToken);
  const expiresAt = new Date(Date.now() + TOKEN_EXPIRES_MINUTES * 60 * 1000);

  await passwordResetModel.create({ userId: user.id, tokenHash, expiresAt });

  const resetUrl = `${env.frontendBaseUrl}/reset-password?token=${rawToken}`;
  await emailService.send({
    to: email,
    subject: 'Reset your Sastranidhi password',
    text: `We received a request to reset your password. This link expires in ${TOKEN_EXPIRES_MINUTES} minutes:\n\n${resetUrl}\n\nIf you didn't request this, you can ignore this email — your password won't change.`,
  });
}

async function resetPassword(rawToken, newPassword) {
  if (typeof newPassword !== 'string' || newPassword.length < 8) {
    throw new ApiError(400, 'invalid_request', 'Password must be at least 8 characters.');
  }

  const tokenHash = sha256Hex(rawToken || '');
  const record = await passwordResetModel.findValidByTokenHash(tokenHash);
  if (!record) {
    throw new ApiError(400, 'invalid_token', 'This password reset link is invalid, expired, or has already been used.');
  }

  const passwordHash = await bcrypt.hash(newPassword, env.security.bcryptSaltRounds);
  await userModel.setPasswordHash(record.user_id, passwordHash);
  await passwordResetModel.markUsed(record.id);
  // A still-live token from an earlier "forgot password" click (e.g. the
  // user requested it twice) shouldn't remain redeemable after one
  // succeeds.
  await passwordResetModel.invalidateAllForUser(record.user_id);

  // A password reset is a strong signal the account may have been
  // compromised — revoke every existing refresh token so any
  // already-issued access stops renewing, and require every device to
  // log in again with the new password. refreshTokenModel.revokeAllForUser
  // already exists (used by POST /auth/logout?everywhere=true).
  await refreshTokenModel.revokeAllForUser(record.user_id);

  await auditLogModel.record({
    userId: record.user_id,
    eventType: 'PASSWORD_RESET',
    metadata: {},
  });
}

module.exports = { requestReset, resetPassword };
