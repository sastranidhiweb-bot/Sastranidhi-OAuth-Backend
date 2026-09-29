// src/routes/social.js
//
// Google/Microsoft OAuth login. Routes only exist when a provider is
// actually configured (see config/passport.js) -- checked again here so
// a misconfigured deployment gets a clear 501 instead of passport
// throwing an opaque "Unknown authentication strategy" error.
//
// returnTo travels through the OAuth "state" parameter, signed with
// stateToken -- NOT req.session. Passport's req.login() (called once the
// provider redirects back) regenerates the session as a fixation defense,
// which would silently wipe a session-stored value between the outbound
// redirect and the callback. This is the exact same issue documented for
// the local login flow in modules 2-3, just one hop further away.

const express = require('express');
const passport = require('../config/passport');
const env = require('../config/env');
const stateToken = require('../utils/stateToken');
const sessionModel = require('../models/sessionModel');
const auditLogModel = require('../models/auditLogModel');
const { sanitizeReturnTo } = require('../utils/returnTo');

const router = express.Router();

function providerConfigured(provider) {
  return provider === 'google' ? Boolean(env.google.clientId) : Boolean(env.microsoft.clientId);
}

function requireConfigured(provider) {
  return (req, res, next) => {
    if (!providerConfigured(provider)) {
      return res.status(501).json({
        error: 'not_configured',
        error_description: `${provider} login is not configured on this server`,
      });
    }
    next();
  };
}

/** Shared callback handling for both providers: establish the SSO session exactly like local login does, then redirect to returnTo. */
function completeSocialLogin(provider) {
  return (req, res) => {
    const decodedState = stateToken.verify(req.query.state);
    const returnTo = sanitizeReturnTo(decodedState?.returnTo);

    req.login(req.user, async (err) => {
      if (err) {
        return res.redirect(`${env.frontendBaseUrl}/login?error=social_login_failed`);
      }

      await sessionModel.upsert({
        sessionId: req.sessionID,
        userId: req.user.id,
        ipAddress: req.ip,
        deviceInfo: req.headers['user-agent'],
        expiresAt: new Date(Date.now() + env.session.maxAgeMs),
      });

      await auditLogModel.record({
        userId: req.user.id,
        eventType: 'LOGIN_SUCCESS',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        metadata: { via: provider },
      });

      // No pending returnTo (e.g. "Continue with Google" clicked directly
      // on the portal's login page, no child-app request in flight) —
      // land on the portal itself, not this backend's bare API root.
      res.redirect(returnTo || env.frontendBaseUrl);
    });
  };
}

// ---------------- Google ----------------

router.get('/google', requireConfigured('google'), (req, res, next) => {
  const state = stateToken.sign(
    { returnTo: typeof req.query.returnTo === 'string' ? req.query.returnTo : null },
    { expiresInSeconds: 300 }
  );
  passport.authenticate('google', { scope: ['profile', 'email'], state })(req, res, next);
});

router.get(
  '/google/callback',
  requireConfigured('google'),
  passport.authenticate('google', { session: false, failureRedirect: `${env.frontendBaseUrl}/login?error=google_failed` }),
  completeSocialLogin('google')
);

// ---------------- Microsoft ----------------

router.get('/microsoft', requireConfigured('microsoft'), (req, res, next) => {
  const state = stateToken.sign(
    { returnTo: typeof req.query.returnTo === 'string' ? req.query.returnTo : null },
    { expiresInSeconds: 300 }
  );
  passport.authenticate('microsoft', { state })(req, res, next);
});

router.get(
  '/microsoft/callback',
  requireConfigured('microsoft'),
  passport.authenticate('microsoft', {
    session: false,
    failureRedirect: `${env.frontendBaseUrl}/login?error=microsoft_failed`,
  }),
  completeSocialLogin('microsoft')
);

module.exports = router;
