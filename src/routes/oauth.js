// src/routes/oauth.js
const express = require('express');
const asyncHandler = require('../utils/asyncHandler');
const ApiError = require('../utils/ApiError');

const authRateLimiter = require('../middleware/authRateLimiter');

const clientService = require('../services/clientService');
const authorizationCodeService = require('../services/authorizationCodeService');
const tokenService = require('../services/tokenService');
const refreshTokenModel = require('../models/refreshTokenModel');
const userModel = require('../models/userModel');
const { verifyPkce } = require('../utils/crypto');
const env = require('../config/env');

const router = express.Router();

// ------------------------------------------------------------------
// GET /oauth/authorize
//
// Standard Authorization Code flow entry point. Validates the client and
// redirect_uri first (see comment below), then checks the session — this
// is also where "silent SSO" happens: if the browser already carries a
// valid session cookie from a previous login at a different child app,
// that check passes immediately with no login screen at all.
// ------------------------------------------------------------------
router.get(
  '/authorize',
  asyncHandler(async (req, res) => {
    const {
      response_type,
      client_id,
      redirect_uri,
      scope,
      state,
      code_challenge,
      code_challenge_method,
      nonce,
    } = req.query;

    // Validate the client and redirect_uri BEFORE checking/prompting for
    // login. Per the OAuth 2.0 Security BCP, an invalid redirect_uri must
    // never be allowed to reach a point where the user authenticates —
    // otherwise the login page itself becomes a phishing/open-redirect
    // primitive ("log in here, then get bounced to attacker.example.com").
    if (response_type !== 'code') {
      throw new ApiError(400, 'unsupported_response_type', 'Only response_type=code is supported');
    }
    if (!client_id || !redirect_uri) {
      throw new ApiError(400, 'invalid_request', 'client_id and redirect_uri are required');
    }
    if (code_challenge && code_challenge_method && code_challenge_method !== 'S256') {
      throw new ApiError(400, 'invalid_request', 'Only code_challenge_method=S256 is supported');
    }

    const client = await clientService.loadPublicClient(client_id);
    clientService.assertRedirectUriRegistered(client, redirect_uri);

    // Only now — with a validated client and redirect_uri — do we touch
    // the session. This is also where "silent SSO" happens: if the browser
    // already carries a valid session cookie from a previous login at a
    // different child app, this check passes immediately with no login
    // screen at all.
    if (!req.isAuthenticated || !req.isAuthenticated()) {
      // Was: redirect to this backend's own placeholder /auth/login-page
      // ("replace with the React auth UI later" — see routes/auth.js).
      // Now: send the browser to the portal's own branded login page,
      // still carrying returnTo so the portal can send it straight back
      // here (now with a session cookie) once login succeeds — the exact
      // same silent-completion mechanism as before, just fronted by a
      // real page instead of raw HTML served by this backend.
      const returnTo = encodeURIComponent(req.originalUrl);
      return res.redirect(`${env.frontendBaseUrl}/login?returnTo=${returnTo}`);
    }

    // All current clients are first-party Sastranidhi applications, so we
    // auto-approve rather than showing a consent screen (this is the
    // "Silent SSO" behavior from the architecture doc). If/when a
    // third-party client is ever registered, a consent step belongs here.
    const code = await authorizationCodeService.issueCode({
      userId: req.user.id,
      clientId: client_id,
      redirectUri: redirect_uri,
      scope: scope || client.scopes,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method,
      nonce,
    });

    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('code', code);
    if (state) redirectUrl.searchParams.set('state', state);

    res.redirect(redirectUrl.toString());
  })
);

// ------------------------------------------------------------------
// POST /oauth/token
//
// grant_type=authorization_code  -> exchange a code for tokens
// grant_type=refresh_token       -> rotate a refresh token for new tokens
// ------------------------------------------------------------------
router.post(
  '/token',
  authRateLimiter,
  asyncHandler(async (req, res) => {
    const { grant_type } = req.body;

    if (grant_type === 'authorization_code') {
      return handleAuthorizationCodeGrant(req, res);
    }
    if (grant_type === 'refresh_token') {
      return handleRefreshTokenGrant(req, res);
    }
    throw new ApiError(400, 'unsupported_grant_type', `grant_type "${grant_type}" is not supported`);
  })
);

async function handleAuthorizationCodeGrant(req, res) {
  const { code, redirect_uri, client_id, client_secret, code_verifier } = req.body;

  if (!code || !redirect_uri || !client_id) {
    throw new ApiError(400, 'invalid_request', 'code, redirect_uri and client_id are required');
  }

  await clientService.authenticateClient(client_id, client_secret);

  const stored = await authorizationCodeService.consumeCode(code);
  if (!stored) {
    throw new ApiError(400, 'invalid_grant', 'Authorization code is invalid, expired, or already used');
  }
  if (stored.clientId !== client_id || stored.redirectUri !== redirect_uri) {
    throw new ApiError(400, 'invalid_grant', 'client_id/redirect_uri do not match the authorization request');
  }
  if (stored.codeChallenge) {
    if (!code_verifier || !verifyPkce(code_verifier, stored.codeChallenge)) {
      throw new ApiError(400, 'invalid_grant', 'PKCE verification failed');
    }
  }

  const user = await userModel.findById(stored.userId);
  if (!user) {
    throw new ApiError(400, 'invalid_grant', 'User for this authorization code no longer exists');
  }

  await respondWithTokenSet(res, user, client_id, stored.scope, { nonce: stored.nonce });
}

async function handleRefreshTokenGrant(req, res) {
  const { refresh_token, client_id, client_secret } = req.body;

  if (!refresh_token || !client_id) {
    throw new ApiError(400, 'invalid_request', 'refresh_token and client_id are required');
  }

  await clientService.authenticateClient(client_id, client_secret);

  const stored = await refreshTokenModel.findValidByRawToken(refresh_token);
  if (!stored || stored.client_id !== client_id) {
    throw new ApiError(400, 'invalid_grant', 'Refresh token is invalid, expired, or revoked');
  }

  // Rotation: the presented refresh token is single-use. Revoking it here
  // means a stolen-and-replayed old refresh token stops working the moment
  // the legitimate client rotates — a standard refresh-token-theft defense.
  await refreshTokenModel.revokeByRawToken(refresh_token);

  const user = await userModel.findById(stored.user_id);
  if (!user) {
    throw new ApiError(400, 'invalid_grant', 'User for this refresh token no longer exists');
  }

  // Per RFC 6749 §6: if the client doesn't request a narrower scope, the
  // new token set inherits the scope originally granted. No nonce here —
  // nonce is only meaningful on the initial authentication event.
  await respondWithTokenSet(res, user, client_id, stored.scope);
}

async function respondWithTokenSet(res, user, clientId, scope, { nonce } = {}) {
  const { token: accessToken, expiresIn } = await tokenService.issueAccessToken(user, {
    clientId,
    scope,
  });
  const refreshToken = await tokenService.issueRefreshToken(user, clientId, scope);

  const responseBody = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: Math.floor(expiresIn / 1000),
    refresh_token: refreshToken,
    scope: scope || undefined,
  };

  // OIDC: only issue an id_token when the client actually requested the
  // "openid" scope — that scope is what turns a plain OAuth2 grant into an
  // OpenID Connect authentication event.
  const scopeList = (scope || '').split(' ').filter(Boolean);
  if (scopeList.includes('openid')) {
    responseBody.id_token = await tokenService.issueIdToken(user, { clientId, nonce, scope });
  }

  res.json(responseBody);
}

// ------------------------------------------------------------------
// POST /oauth/revoke  (RFC 7009-style)
// ------------------------------------------------------------------
router.post(
  '/revoke',
  authRateLimiter,
  asyncHandler(async (req, res) => {
    const { token, token_type_hint, client_id, client_secret } = req.body;

    if (!token || !client_id) {
      throw new ApiError(400, 'invalid_request', 'token and client_id are required');
    }
    await clientService.authenticateClient(client_id, client_secret);

    if (token_type_hint === 'refresh_token') {
      await refreshTokenModel.revokeByRawToken(token);
    } else {
      // Try access token first (blacklist by jti), then fall back to
      // treating it as a refresh token — per RFC 7009 servers should not
      // reveal which case applied.
      try {
        const decoded = await tokenService.verifyAccessToken(token);
        await tokenService.blacklistAccessToken(decoded);
      } catch {
        await refreshTokenModel.revokeByRawToken(token);
      }
    }

    // RFC 7009: always respond 200, whether or not the token was valid.
    res.status(200).json({});
  })
);

module.exports = router;
