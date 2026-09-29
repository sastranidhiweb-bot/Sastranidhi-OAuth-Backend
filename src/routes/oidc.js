// src/routes/oidc.js
const express = require('express');
const asyncHandler = require('../utils/asyncHandler');
const env = require('../config/env');
const keys = require('../config/keys');
const requireAccessToken = require('../middleware/requireAccessToken');
const userModel = require('../models/userModel');

const router = express.Router();

// ------------------------------------------------------------------
// GET /.well-known/openid-configuration
//
// The fixed, spec-mandated discovery path. Child apps' OIDC libraries
// fetch this once to learn every other endpoint below, rather than
// hardcoding them.
// ------------------------------------------------------------------
router.get('/.well-known/openid-configuration', (req, res) => {
  res.json({
    issuer: env.issuer,
    authorization_endpoint: `${env.issuer}/oauth/authorize`,
    token_endpoint: `${env.issuer}/oauth/token`,
    userinfo_endpoint: `${env.issuer}/oidc/userinfo`,
    jwks_uri: `${env.issuer}/oidc/jwks`,
    revocation_endpoint: `${env.issuer}/oauth/revoke`,
    scopes_supported: ['openid', 'profile', 'email'],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    code_challenge_methods_supported: ['S256'],
    claims_supported: [
      'sub',
      'email',
      'email_verified',
      'name',
      'given_name',
      'family_name',
      'preferred_username',
      'picture',
    ],
  });
});

// ------------------------------------------------------------------
// GET /oidc/jwks
//
// The public half of the RS256 keypair, as a JWK Set. This is the whole
// point of moving to asymmetric signing in this module: any child app can
// fetch this and verify a token's signature itself, with no shared secret.
// ------------------------------------------------------------------
router.get('/oidc/jwks', (req, res) => {
  res.json({ keys: [keys.jwk] });
});

// ------------------------------------------------------------------
// GET /oidc/userinfo
//
// Standard OIDC userinfo endpoint. Claims are gated by the scope the
// access token was actually issued with (RFC/OIDC convention: no "email"
// scope -> no email claim, etc). Profile fields are read fresh from the
// database rather than trusted from the token, since userinfo is meant to
// reflect the user's *current* profile, not a snapshot from token issuance.
//
// "apps" is included unconditionally — it's a Sastranidhi-specific
// extension claim (not part of the OIDC spec), included here for
// consistency with the access token's own "apps" claim.
// ------------------------------------------------------------------
router.get(
  '/oidc/userinfo',
  requireAccessToken,
  asyncHandler(async (req, res) => {
    const user = await userModel.findById(req.token.sub);
    if (!user) {
      return res.status(404).json({ error: 'not_found', error_description: 'User no longer exists' });
    }

    const scopes = (req.token.scope || '').split(' ').filter(Boolean);
    const claims = { sub: String(user.id), apps: req.token.apps };

    if (scopes.includes('email')) {
      claims.email = user.email;
      claims.email_verified = Boolean(user.email_verified_at);
    }
    if (scopes.includes('profile')) {
      claims.name = [user.first_name, user.last_name].filter(Boolean).join(' ') || undefined;
      claims.given_name = user.first_name || undefined;
      claims.family_name = user.last_name || undefined;
      claims.preferred_username = user.username;
      claims.picture = user.profile_photo || undefined;
    }

    res.json(claims);
  })
);

module.exports = router;
