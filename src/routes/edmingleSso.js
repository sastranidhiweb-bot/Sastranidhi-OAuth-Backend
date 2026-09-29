// src/routes/edmingleSso.js
//
// Custom SSO bridge for Edmingle LMS (third-party SaaS, no codebase
// access — direct HS256 JWT redirection, NOT the OAuth2/OIDC code flow
// used by Paripraśna). Mirrors the same "silent SSO" pattern as
// GET /oauth/authorize (see routes/oauth.js): validate inputs first,
// check the Redis-backed session, bounce to the portal login if absent,
// then redirect back here automatically once a session exists.
//
// Docs: Edmingle Admin Dashboard -> Settings -> Integration -> Advanced.

const express = require('express');
const jwt = require('jsonwebtoken');

const asyncHandler = require('../utils/asyncHandler');
const ApiError = require('../utils/ApiError');
const env = require('../config/env');
const logger = require('../config/logger');

const router = express.Router();

// Edmingle's own doc: the generated token "will expire or not be useful
// after 120 secs of initiation" — this is a strict Edmingle-side
// requirement, not something we control, so it's hardcoded rather than
// pulled from env.
const EDMINGLE_TOKEN_TTL_SECONDS = 120;

/**
 * Edmingle sends redirect_url as the bare LMS host (e.g.
 * "demoacademy.edmingle.com"), not a full URL — their own example in the
 * doc shows it unprefixed. Guard against both cases, and against
 * anything that isn't actually pointing at an edmingle.com host, since
 * this value drives a 302 redirect (open-redirect risk otherwise).
 */
function buildSafeEdmingleRedirect(rawRedirectUrl) {
  if (!rawRedirectUrl || typeof rawRedirectUrl !== 'string') return null;

  const withScheme = /^https?:\/\//i.test(rawRedirectUrl) ? rawRedirectUrl : `https://${rawRedirectUrl}`;

  let target;
  try {
    target = new URL(withScheme);
  } catch {
    return null;
  }

  const allowedHost = (() => {
    try {
      return new URL(env.edmingle.lmsUrl).host;
    } catch {
      return null;
    }
  })();

  // Accept either the exact configured LMS host, or any *.edmingle.com
  // subdomain (Edmingle provisions one per academy) — never an arbitrary
  // external domain.
  const isConfiguredHost = allowedHost && target.host === allowedHost;
  const isEdmingleHost = /\.edmingle\.com$/i.test(target.host) || target.host === 'edmingle.com';

  if (!isConfiguredHost && !isEdmingleHost) return null;

  return target;
}

// ------------------------------------------------------------------
// GET /auth/edmingle/sso
//
// Entry point Edmingle redirects unauthenticated LMS visitors to, e.g.:
//   /auth/edmingle/sso?redirect_url=demoacademy.edmingle.com
//   /auth/edmingle/sso?redirect_url=...&edmingle_redirect_url=<url-encoded deep link>
// ------------------------------------------------------------------
router.get(
  '/edmingle/sso',
  asyncHandler(async (req, res) => {
    const { redirect_url: redirectUrl, edmingle_redirect_url: edmingleRedirectUrl } = req.query;

    if (!env.edmingle.ssoSecret) {
      // Fail loudly in server logs but don't leak config state to the
      // browser — this is a deployment mistake, not a client error.
      logger.error('Edmingle SSO route hit but EDMINGLE_SSO_SECRET is not configured');
      throw new ApiError(500, 'server_misconfigured', 'Edmingle SSO is not configured on this server');
    }

    const targetUrl = buildSafeEdmingleRedirect(redirectUrl);
    if (!targetUrl) {
      throw new ApiError(400, 'invalid_request', 'redirect_url is missing or not a recognized Edmingle domain');
    }

    // Same silent-SSO mechanic as /oauth/authorize: no session yet ->
    // send to the portal's login page with a returnTo that points right
    // back here (this exact URL, params intact), so login success
    // redirects straight back and this handler runs again — this time
    // authenticated, no login screen shown twice.
    if (!req.isAuthenticated || !req.isAuthenticated()) {
      const returnTo = encodeURIComponent(req.originalUrl);
      return res.redirect(`${env.frontendBaseUrl}/login?returnTo=${returnTo}`);
    }

    const user = req.user;
    const nowSeconds = Math.floor(Date.now() / 1000);

    const payload = {
      iss: env.issuer,
      iat: nowSeconds,
      exp: nowSeconds + EDMINGLE_TOKEN_TTL_SECONDS,
      first_name: user.first_name || '',
      last_name: user.last_name || '',
      email: user.email,
      contact_number: user.mobile || '',
    };

    const token = jwt.sign(payload, env.edmingle.ssoSecret, { algorithm: 'HS256' });

    targetUrl.searchParams.set('jwt', token);
    if (edmingleRedirectUrl && typeof edmingleRedirectUrl === 'string') {
      // Edmingle's doc explicitly asks for this to be URL-encoded on the
      // final redirect — URLSearchParams.set() already handles that
      // encoding, so just pass the decoded value through here (don't
      // double-encode a value that arrived from req.query already decoded).
      targetUrl.searchParams.set('edmingle_redirect_url', edmingleRedirectUrl);
    }

    logger.info('Edmingle SSO token issued', { userId: user.id, host: targetUrl.host });

    res.redirect(302, targetUrl.toString());
  })
);

module.exports = router;