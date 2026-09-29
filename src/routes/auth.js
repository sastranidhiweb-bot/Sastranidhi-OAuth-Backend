// src/routes/auth.js
const express = require('express');
const bcrypt = require('bcrypt');
const passport = require('../config/passport');

const asyncHandler = require('../utils/asyncHandler');
const ApiError = require('../utils/ApiError');
const env = require('../config/env');
const stateToken = require('../utils/stateToken');

const userModel = require('../models/userModel');
const sessionModel = require('../models/sessionModel');
const auditLogModel = require('../models/auditLogModel');
const refreshTokenModel = require('../models/refreshTokenModel');
const authRateLimiter = require('../middleware/authRateLimiter');
const requireAccessToken = require('../middleware/requireAccessToken');
const { sanitizeReturnTo } = require('../utils/returnTo');
const verificationService = require('../services/verificationService');
const passwordResetService = require('../services/passwordResetService');

const router = express.Router();

// ------------------------------------------------------------------
// POST /auth/register/start — step 1: submit an email, get a code sent
// ------------------------------------------------------------------
router.post(
  '/register/start',
  authRateLimiter,
  asyncHandler(async (req, res) => {
    const { email } = req.body;
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      throw new ApiError(400, 'invalid_request', 'A valid email address is required');
    }

    const existingUser = await userModel.findByEmail(email);
    if (existingUser) {
      // Same "don't confirm account existence" caution as forgot-password,
      // but here the user is actively trying to register, so a clear
      // message is more useful than silence — this endpoint doesn't leak
      // anything requestReset() below doesn't already avoid leaking for
      // *unauthenticated* lookups elsewhere.
      throw new ApiError(409, 'user_exists', 'An account with this email already exists. Try logging in instead.');
    }

    const result = await verificationService.startVerification(email);
    res.json({ message: 'Verification code sent', ...result });
  })
);

// ------------------------------------------------------------------
// POST /auth/register/resend — same as start, just a clearer name for
// the "Resend Code" button; identical cooldown/rate-limit behavior.
// ------------------------------------------------------------------
router.post(
  '/register/resend',
  authRateLimiter,
  asyncHandler(async (req, res) => {
    const { email } = req.body;
    if (!email || typeof email !== 'string') {
      throw new ApiError(400, 'invalid_request', 'email is required');
    }
    const result = await verificationService.startVerification(email);
    res.json({ message: 'Verification code sent', ...result });
  })
);

// ------------------------------------------------------------------
// POST /auth/register/verify — step 2: submit the code
// ------------------------------------------------------------------
router.post(
  '/register/verify',
  authRateLimiter,
  asyncHandler(async (req, res) => {
    const { email, code } = req.body;
    if (!email || !code) {
      throw new ApiError(400, 'invalid_request', 'email and code are required');
    }
    const result = await verificationService.verifyCode(email, code);
    res.json(result); // { emailVerificationToken }
  })
);

// ------------------------------------------------------------------
// POST /auth/register — step 3: create the account. Requires the
// short-lived emailVerificationToken from /register/verify — this is the
// server-side enforcement that email verification cannot be bypassed by
// a frontend that simply sets emailVerified=true.
// ------------------------------------------------------------------
router.post(
  '/register',
  authRateLimiter,
  asyncHandler(async (req, res) => {
    const { email, username, password, first_name, last_name, mobile, email_verification_token } = req.body;

    if (!email || !username || !password) {
      throw new ApiError(400, 'invalid_request', 'email, username and password are required');
    }
    if (password.length < 8) {
      throw new ApiError(400, 'invalid_request', 'password must be at least 8 characters');
    }
    verificationService.assertEmailVerified(email_verification_token, email);

    const existingByEmail = await userModel.findByEmail(email);
    if (existingByEmail) {
      throw new ApiError(409, 'user_exists', 'A user with this email already exists');
    }
    const existingByUsername = await userModel.findByUsername(username);
    if (existingByUsername) {
      throw new ApiError(409, 'user_exists', 'A user with this username already exists');
    }

    const passwordHash = await bcrypt.hash(password, env.security.bcryptSaltRounds);
    const user = await userModel.create({
      email,
      username,
      passwordHash,
      firstName: first_name,
      lastName: last_name,
      mobile,
      emailVerifiedAt: new Date(),
    });

    await auditLogModel.record({
      userId: user.id,
      eventType: 'USER_REGISTERED',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.status(201).json({ user: userModel.toPublic(user) });
  })
);

// ------------------------------------------------------------------
// POST /auth/forgot-password
// ------------------------------------------------------------------
router.post(
  '/forgot-password',
  authRateLimiter,
  asyncHandler(async (req, res) => {
    const { email } = req.body;
    if (!email) {
      throw new ApiError(400, 'invalid_request', 'email is required');
    }
    await passwordResetService.requestReset(email);
    // Always the same response whether or not the email exists — see the
    // comment in passwordResetService.requestReset for why.
    res.json({ message: 'If an account exists for that email, a reset link has been sent.' });
  })
);

// ------------------------------------------------------------------
// POST /auth/reset-password
// ------------------------------------------------------------------
router.post(
  '/reset-password',
  authRateLimiter,
  asyncHandler(async (req, res) => {
    const { token, password } = req.body;
    if (!token || !password) {
      throw new ApiError(400, 'invalid_request', 'token and password are required');
    }
    await passwordResetService.resetPassword(token, password);
    res.json({ message: 'Password updated. Please log in with your new password.' });
  })
);

// ------------------------------------------------------------------
// POST /auth/login  — establishes the Redis-backed SSO session
// ------------------------------------------------------------------
router.post('/login', authRateLimiter, (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      return res.status(401).json({ error: 'invalid_credentials', error_description: info?.message });
    }

    // returnTo comes from the client (form field), not the session — see
    // the comment on GET /oauth/authorize in routes/oauth.js for why:
    // passport's req.login() regenerates the session as a fixation
    // defense, which would wipe a session-stored value before we could
    // read it back here. Only ever honor a same-origin relative path,
    // never an absolute/external URL, so this can't become an open redirect.
    const { returnTo } = req.body;
    const safeReturnTo = sanitizeReturnTo(returnTo);

    // Password verified, but this account has MFA enabled — don't
    // establish a session yet. Hand back a short-lived, signed challenge
    // token instead; the actual session only gets created once
    // /auth/mfa/challenge verifies the second factor against this exact
    // userId. This is stateless (no server-side "pending login" record),
    // which sidesteps the same session-regenerate timing issue mentioned
    // above entirely, since nothing here touches req.session.
    if (user.mfa_enabled) {
      const mfaToken = stateToken.sign(
        { purpose: 'mfa_challenge', userId: user.id, returnTo: safeReturnTo },
        { expiresInSeconds: env.mfa.challengeExpiresInSeconds }
      );
      return res.json({ mfa_required: true, mfa_token: mfaToken });
    }

    req.login(user, async (loginErr) => {
      if (loginErr) return next(loginErr);

      await sessionModel.upsert({
        sessionId: req.sessionID,
        userId: user.id,
        ipAddress: req.ip,
        deviceInfo: req.headers['user-agent'],
        expiresAt: new Date(Date.now() + env.session.maxAgeMs),
      });

      res.json({ user: userModel.toPublic(user), returnTo: safeReturnTo });
    });
  })(req, res, next);
});

// ------------------------------------------------------------------
// GET /auth/login-page
//
// Minimal, unstyled server-rendered login form. This exists purely so the
// full authorization-code flow can be exercised in a browser before a real
// login/consent frontend exists — replace with the React auth UI later.
// ------------------------------------------------------------------
router.get('/login-page', (req, res) => {
  const returnTo = typeof req.query.returnTo === 'string' ? req.query.returnTo : '';
  res.set('Content-Type', 'text/html').send(`
    <!doctype html>
    <html>
      <body style="font-family: sans-serif; max-width: 360px; margin: 80px auto;">
        <h2>Sastranidhi — Sign in</h2>
        <form id="f">
          <input type="hidden" name="returnTo" value="${returnTo.replace(/"/g, '&quot;')}" />
          <input name="email" type="email" placeholder="Email" required style="display:block;width:100%;margin-bottom:8px;padding:8px;" />
          <input name="password" type="password" placeholder="Password" required style="display:block;width:100%;margin-bottom:8px;padding:8px;" />
          <button type="submit" style="padding:8px 16px;">Sign in</button>
        </form>
        <p id="err" style="color:red;"></p>
        <script>
          document.getElementById('f').addEventListener('submit', async (e) => {
            e.preventDefault();
            const body = Object.fromEntries(new FormData(e.target));
            const res = await fetch('/auth/login', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'include',
              body: JSON.stringify(body),
            });
            const data = await res.json();
            if (!res.ok) {
              document.getElementById('err').textContent = data.error_description || 'Login failed';
              return;
            }
            window.location.href = data.returnTo || '/';
          });
        </script>
      </body>
    </html>
  `);
});

// ------------------------------------------------------------------
// GET /auth/session — is there a live SSO session right now?
// ------------------------------------------------------------------
router.get('/session', (req, res) => {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return res.json({ authenticated: true, user: userModel.toPublic(req.user) });
  }
  res.json({ authenticated: false });
});

// ------------------------------------------------------------------
// POST /auth/logout — destroys the SSO session (Single Logout baseline)
// ------------------------------------------------------------------
router.post(
  '/logout',
  asyncHandler(async (req, res) => {
    const userId = req.user?.id;
    const sessionId = req.sessionID;
    const everywhere = req.query.everywhere === 'true';

    await sessionModel.remove(sessionId);

    if (everywhere && userId) {
      await refreshTokenModel.revokeAllForUser(userId);
    }

    if (userId) {
      await auditLogModel.record({
        userId,
        eventType: 'LOGOUT',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        metadata: { everywhere },
      });
    }

    req.logout(() => {
      req.session.destroy(() => {
        res.clearCookie(env.session.cookieName);
        res.json({ message: 'Logged out' });
      });
    });
  })
);

// ------------------------------------------------------------------
// GET /auth/me — decode the caller's own access token (demonstration /
// test endpoint; child apps will implement their own equivalent).
// ------------------------------------------------------------------
router.get('/me', requireAccessToken, (req, res) => {
  res.json({ token: req.token });
});

module.exports = router;
