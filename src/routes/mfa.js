// src/routes/mfa.js
//
// TOTP-based MFA setup/verification/disable, plus the second-factor
// challenge step that /auth/login redirects into when a user with MFA
// enabled logs in (see routes/auth.js).

const express = require('express');
const crypto = require('crypto');

const asyncHandler = require('../utils/asyncHandler');
const ApiError = require('../utils/ApiError');
const env = require('../config/env');

const totp = require('../utils/totp');
const stateToken = require('../utils/stateToken');
const userModel = require('../models/userModel');
const sessionModel = require('../models/sessionModel');
const mfaRecoveryCodeModel = require('../models/mfaRecoveryCodeModel');
const auditLogModel = require('../models/auditLogModel');

const router = express.Router();

const RECOVERY_CODE_COUNT = 8;

function requireLoggedIn(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    throw new ApiError(401, 'unauthorized', 'You must be logged in to manage MFA');
  }
  next();
}

function generateRecoveryCode() {
  // 10 hex chars (40 bits) -- short enough to type from a printed sheet,
  // long enough that guessing one is not a realistic attack.
  return crypto.randomBytes(5).toString('hex');
}

/** True if `code` matches either a current TOTP code or an unused recovery code — used by both /disable and /challenge, which both accept either factor. */
async function verifySecondFactor(user, code) {
  if (totp.verify(user.mfa_secret, code)) return true;
  if (await mfaRecoveryCodeModel.consumeIfValid(user.id, code)) return true;
  return false;
}

// ------------------------------------------------------------------
// POST /auth/mfa/setup — generates a new secret, not yet enabled
// ------------------------------------------------------------------
router.post(
  '/setup',
  requireLoggedIn,
  asyncHandler(async (req, res) => {
    const secret = totp.generateSecret();
    await userModel.setPendingMfaSecret(req.user.id, secret);

    const otpauthUrl = totp.buildOtpauthUri({
      secretBase32: secret,
      accountLabel: req.user.email,
      issuer: env.mfa.issuerName,
    });

    res.json({ secret, otpauth_url: otpauthUrl });
  })
);

// ------------------------------------------------------------------
// POST /auth/mfa/verify-setup   body: { code }
// Confirms the user can actually generate a valid code before MFA
// becomes mandatory on login — this is what prevents someone from
// locking themselves out by mistyping the secret into their app.
// ------------------------------------------------------------------
router.post(
  '/verify-setup',
  requireLoggedIn,
  asyncHandler(async (req, res) => {
    const user = await userModel.findById(req.user.id);
    if (!user.mfa_secret) {
      throw new ApiError(400, 'invalid_request', 'Call /auth/mfa/setup first');
    }

    if (!totp.verify(user.mfa_secret, req.body.code)) {
      throw new ApiError(400, 'invalid_code', 'That code did not verify — check your authenticator app and try again');
    }

    await userModel.enableMfa(user.id);

    const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
    await mfaRecoveryCodeModel.replaceAllForUser(user.id, recoveryCodes);

    await auditLogModel.record({
      userId: user.id,
      eventType: 'MFA_ENABLED',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.json({
      message: 'MFA enabled.',
      recovery_codes: recoveryCodes,
      recovery_codes_notice:
        'Save these now — each works once if you lose access to your authenticator app, and they will not be shown again.',
    });
  })
);

// ------------------------------------------------------------------
// POST /auth/mfa/disable   body: { code }  (TOTP code OR a recovery code)
// ------------------------------------------------------------------
router.post(
  '/disable',
  requireLoggedIn,
  asyncHandler(async (req, res) => {
    const user = await userModel.findById(req.user.id);
    if (!user.mfa_enabled) {
      throw new ApiError(400, 'invalid_request', 'MFA is not enabled on this account');
    }

    if (!(await verifySecondFactor(user, req.body.code))) {
      throw new ApiError(400, 'invalid_code', 'That code did not verify');
    }

    await userModel.disableMfa(user.id);
    await mfaRecoveryCodeModel.deleteAllForUser(user.id);

    await auditLogModel.record({
      userId: user.id,
      eventType: 'MFA_DISABLED',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.json({ message: 'MFA disabled.' });
  })
);

// ------------------------------------------------------------------
// POST /auth/mfa/challenge   body: { mfa_token, code }
//
// This is the SECOND step of login for an MFA-enabled account —
// /auth/login (routes/auth.js) verifies the password and, instead of
// establishing a session immediately, returns an mfa_token here instead.
// No session exists yet; mfa_token (a stateToken, not a session or JWT)
// is what proves the password step already passed for this specific user.
// ------------------------------------------------------------------
router.post(
  '/challenge',
  asyncHandler(async (req, res) => {
    const { mfa_token, code } = req.body;
    const decoded = stateToken.verify(mfa_token);

    if (!decoded || decoded.purpose !== 'mfa_challenge' || !decoded.userId) {
      throw new ApiError(400, 'invalid_request', 'mfa_token is invalid or has expired — please log in again');
    }

    const user = await userModel.findById(decoded.userId);
    if (!user || user.status !== 'active' || !user.mfa_enabled) {
      throw new ApiError(400, 'invalid_request', 'This account can no longer complete an MFA challenge');
    }

    if (!(await verifySecondFactor(user, code))) {
      await auditLogModel.record({
        userId: user.id,
        eventType: 'LOGIN_FAILED',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        metadata: { reason: 'mfa_invalid' },
      });
      throw new ApiError(401, 'invalid_code', 'That code did not verify');
    }

    req.login(user, async (err) => {
      if (err) throw err;

      await sessionModel.upsert({
        sessionId: req.sessionID,
        userId: user.id,
        ipAddress: req.ip,
        deviceInfo: req.headers['user-agent'],
        expiresAt: new Date(Date.now() + env.session.maxAgeMs),
      });

      await auditLogModel.record({
        userId: user.id,
        eventType: 'LOGIN_SUCCESS',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        metadata: { via: 'mfa' },
      });

      const returnTo =
        typeof decoded.returnTo === 'string' && decoded.returnTo.startsWith('/') ? decoded.returnTo : null;
      res.json({ user: userModel.toPublic(user), returnTo });
    });
  })
);

module.exports = router;
